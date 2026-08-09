//! Vault 密钥集合 + 创建 / 解锁 / 改密码 / 旋转密钥的高层 API。
//!
//! 这是 crate 对外的核心面板。每个 vault 持久化的部分是 [`EncryptedKeySet`],
//! 解锁后得到 [`UnlockedVault`](密钥常驻内存,zeroize on drop)。

use serde::{Deserialize, Serialize};

use crate::aead::{unwrap_key, wrap_key, WrappedKey};
use crate::error::{CryptoError, Result};
use crate::kdf::{derive_muk, KdfParams};
use crate::keys::{ItemKekKey, KeyEncryptionKey, SymmetricKey, VaultMasterKey};
use crate::random;
// SK 已移除(ADR-001):MUK = Argon2id(password, salt),无第二因子。

/// 当前 EncryptedKeySet 的格式版本。
pub const KEYSET_FORMAT_VERSION: u16 = 1;

/// 16 字节随机 ID(account / vault)。
pub type Id = [u8; 16];

/// 创建一个新 vault 时的一次性产物:既包含可持久化的 [`EncryptedKeySet`],
/// 也包含立即可用的 [`UnlockedVault`]。
///
/// 调用者应当:
/// 1. 把 `encrypted` 写盘 / 同步
/// 2. 用 `unlocked` 直接进行后续 item 加密,不必再走一遍解锁流程
pub struct VaultKeySet {
    /// 持久化部分。
    pub encrypted: EncryptedKeySet,
    /// 内存中已解开的密钥,可立即用于 item 加密。
    pub unlocked: UnlockedVault,
}

/// vault 持久化部分。**只**包含密文与公开参数,不含任何明文密钥。
///
/// 可以放心 `serde_json::to_string`、写盘、同步上云。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedKeySet {
    /// 格式版本,客户端按此判断兼容性。
    pub version: u16,
    /// 16 字节 account ID。
    #[serde(with = "id_bytes")]
    pub account_id: Id,
    /// 16 字节 vault ID。
    #[serde(with = "id_bytes")]
    pub vault_id: Id,
    /// KDF 参数 + salt。
    pub kdf: KdfParams,
    /// MUK 包装的 KEK。AAD 中已绑定 kdf 参数,防降级。
    pub wrapped_kek: WrappedKey,
    /// KEK 包装的 VMK。
    pub wrapped_vmk: WrappedKey,
    /// VMK 包装的 IKEK。
    pub wrapped_ikek: WrappedKey,
}

/// 解锁后的 vault 上下文。持有四把密钥,`Drop` 时全部 zeroize。
pub struct UnlockedVault {
    /// account ID。
    pub account_id: Id,
    /// vault ID。
    pub vault_id: Id,
    pub(crate) kek: KeyEncryptionKey,
    /// 当前 VMK。MVP 之外仅在 `rotate_vault_key` 中替换;item 加密走 IKEK,不直接读 VMK。
    #[allow(dead_code)]
    pub(crate) vmk: VaultMasterKey,
    pub(crate) ikek: ItemKekKey,
}

impl core::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("account_id", &hex16(&self.account_id))
            .field("vault_id", &hex16(&self.vault_id))
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

fn hex16(id: &Id) -> String {
    let mut s = String::with_capacity(32);
    for b in id {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 用主密码创建一个全新 vault(ADR-001:无 Secret Key 第二因子)。
///
/// 流程:
/// 1. 生成 account_id / vault_id / KDF salt(32B random)
/// 2. Argon2id(memory 128 MiB)派生 MUK
/// 3. 各层生成全新随机密钥 KEK / VMK / IKEK
/// 4. 自上而下包装(MUK 包 KEK,KEK 包 VMK,VMK 包 IKEK)
/// 5. 返回包含密文与 unlocked 上下文的 [`VaultKeySet`]
pub fn create_vault_keys(master_password: &str) -> Result<VaultKeySet> {
    let account_id: Id = random::bytes::<16>()?;
    let vault_id: Id = random::bytes::<16>()?;
    let kdf = KdfParams::generate_default()?;

    let muk = derive_muk(master_password, &kdf)?;

    let kek = KeyEncryptionKey::generate()?;
    let vmk = VaultMasterKey::generate()?;
    let ikek = ItemKekKey::generate()?;

    let wrapped_kek = wrap_key(&muk.0, &kek.0, &aad_for_kek(&account_id, &vault_id, &kdf))?;
    let wrapped_vmk = wrap_key(&kek.0, &vmk.0, &aad_for_vmk(&account_id, &vault_id))?;
    let wrapped_ikek = wrap_key(&vmk.0, &ikek.0, &aad_for_ikek(&vault_id))?;

    let encrypted = EncryptedKeySet {
        version: KEYSET_FORMAT_VERSION,
        account_id,
        vault_id,
        kdf,
        wrapped_kek,
        wrapped_vmk,
        wrapped_ikek,
    };
    let unlocked = UnlockedVault {
        account_id,
        vault_id,
        kek,
        vmk,
        ikek,
    };
    Ok(VaultKeySet {
        encrypted,
        unlocked,
    })
}

/// 用主密码 + 持久化的 [`EncryptedKeySet`] 解锁 vault(ADR-001:无 SK)。
///
/// 错误密码 / 任何字段被篡改都返回 [`CryptoError::DecryptFailed`]。
/// **不**告诉调用者具体原因 —— 防止给攻击者提供时序与文案上的反馈。
pub fn unlock_vault(
    master_password: &str,
    keyset: &EncryptedKeySet,
) -> Result<UnlockedVault> {
    if keyset.version != KEYSET_FORMAT_VERSION {
        return Err(CryptoError::UnsupportedVersion(keyset.version));
    }
    keyset.kdf.validate()?;

    let muk = derive_muk(master_password, &keyset.kdf)?;

    let kek_inner = unwrap_key(
        &muk.0,
        &keyset.wrapped_kek,
        &aad_for_kek(&keyset.account_id, &keyset.vault_id, &keyset.kdf),
    )?;
    let kek = KeyEncryptionKey::from_symmetric(kek_inner);

    let vmk_inner = unwrap_key(
        &kek.0,
        &keyset.wrapped_vmk,
        &aad_for_vmk(&keyset.account_id, &keyset.vault_id),
    )?;
    let vmk = VaultMasterKey::from_symmetric(vmk_inner);

    let ikek_inner = unwrap_key(
        &vmk.0,
        &keyset.wrapped_ikek,
        &aad_for_ikek(&keyset.vault_id),
    )?;
    let ikek = ItemKekKey::from_symmetric(ikek_inner);

    Ok(UnlockedVault {
        account_id: keyset.account_id,
        vault_id: keyset.vault_id,
        kek,
        vmk,
        ikek,
    })
}

/// 修改主密码(ADR-001:无 SK)。生成新 KDF salt,用新 MUK 重新包装现有 KEK。
///
/// VMK / IKEK / item 全部不变 —— 也就是说,改密码不需要触碰 vault 数据。
pub fn change_master_password(
    old_password: &str,
    new_password: &str,
    current: &EncryptedKeySet,
) -> Result<EncryptedKeySet> {
    if new_password.is_empty() {
        return Err(CryptoError::InvalidArgument("new password is empty"));
    }

    // 第一步:解锁,确认旧密码正确
    let unlocked = unlock_vault(old_password, current)?;

    // 第二步:用新参数重新派生 MUK
    let new_kdf = KdfParams::generate_default()?;
    let new_muk = derive_muk(new_password, &new_kdf)?;

    // 第三步:用新 MUK 重新包装 KEK
    let wrapped_kek = wrap_key(
        &new_muk.0,
        &unlocked.kek.0,
        &aad_for_kek(&current.account_id, &current.vault_id, &new_kdf),
    )?;

    Ok(EncryptedKeySet {
        version: current.version,
        account_id: current.account_id,
        vault_id: current.vault_id,
        kdf: new_kdf,
        wrapped_kek,
        wrapped_vmk: current.wrapped_vmk.clone(),
        wrapped_ikek: current.wrapped_ikek.clone(),
    })
}

/// 旋转 VMK。生成新 VMK,用 KEK 重新包装,IKEK 用新 VMK 重新包装。
///
/// IKEK 自身**密钥不变**,因此所有 item 的 wrapped_item_key 与密文都不需要改 ——
/// 这正是引入 VMK / IKEK 两层的好处。
///
/// 调用方:本函数返回的 [`EncryptedKeySet`] 应替换持久化的旧版本,
/// 同时获得一份新的 [`UnlockedVault`](VMK 已替换,KEK / IKEK 不变)。
pub fn rotate_vault_key(
    unlocked: &UnlockedVault,
    current: &EncryptedKeySet,
) -> Result<(EncryptedKeySet, UnlockedVault)> {
    if current.account_id != unlocked.account_id || current.vault_id != unlocked.vault_id {
        return Err(CryptoError::InvalidArgument("keyset/vault id mismatch"));
    }

    let new_vmk = VaultMasterKey::generate()?;

    let wrapped_vmk = wrap_key(
        &unlocked.kek.0,
        &new_vmk.0,
        &aad_for_vmk(&current.account_id, &current.vault_id),
    )?;
    let wrapped_ikek = wrap_key(
        &new_vmk.0,
        &unlocked.ikek.0,
        &aad_for_ikek(&current.vault_id),
    )?;

    let next_keyset = EncryptedKeySet {
        version: current.version,
        account_id: current.account_id,
        vault_id: current.vault_id,
        kdf: current.kdf.clone(),
        wrapped_kek: current.wrapped_kek.clone(),
        wrapped_vmk,
        wrapped_ikek,
    };

    let next_unlocked = UnlockedVault {
        account_id: unlocked.account_id,
        vault_id: unlocked.vault_id,
        // KEK 与 IKEK 必须重新生成(不能 clone),用 unwrap 的方式从新 keyset 解出来
        kek: KeyEncryptionKey::from_symmetric(SymmetricKey::try_from_slice(
            unlocked.kek.expose_secret(),
        )?),
        vmk: new_vmk,
        ikek: ItemKekKey::from_symmetric(SymmetricKey::try_from_slice(
            unlocked.ikek.expose_secret(),
        )?),
    };

    Ok((next_keyset, next_unlocked))
}

// ---------- 生物识别 ----------

/// 启用生物识别后,本地需要持久化的「信封」。
///
/// 设计:
/// - 调用方拿到 [`BiometricUnlockSetup`] 后,**`wrapper_key` 必须存到 OS keychain**(由生物识别保护),
///   `envelope` 存到磁盘(典型:与 vault 同目录的 `biometric.envelope.json`)
/// - 解锁时调 [`unlock_via_biometric`]:Dart 经生物识别从 keychain 取 `wrapper_key`,
///   拿 disk 上的 `envelope`,加 keyset → Rust 把 KEK 解出来 → 沿原密钥层次重建 UnlockedVault
///
/// 安全属性:
/// - wrapper_key 永远只在 OS 安全存储 + 内存中存在,不写应用磁盘
/// - 主密码改变 → 调用方应主动 `disable` 然后 re-enable;旧 envelope 仍然解得开但 KEK 必然过期
///   (设计上更安全的做法是每次 change_master_password 后强制 wipe 旧 envelope,由 ffi_bridge 负责)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BiometricEnvelope {
    /// 与 EncryptedKeySet.version 同步,客户端按此判断兼容性。
    pub version: u16,
    /// 本 envelope 关联的 vault_id(必须与解锁时的 keyset.vault_id 一致)。
    #[serde(with = "id_bytes")]
    pub vault_id: Id,
    /// 用 wrapper_key 包装的 KEK。
    pub wrapped_kek: WrappedKey,
}

/// `enable_biometric_unlock` 的返回值。
pub struct BiometricUnlockSetup {
    /// 32 字节随机 wrapper_key,**调用方必须存到 OS keychain**(生物识别保护),不要写应用磁盘。
    pub wrapper_key: [u8; 32],
    /// 持久化的信封,存到磁盘。
    pub envelope: BiometricEnvelope,
}

const AAD_BIOMETRIC_PREFIX: &[u8] = b"root-key/biometric/v1/";

fn aad_for_biometric(vault_id: &Id) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_BIOMETRIC_PREFIX.len() + 16);
    out.extend_from_slice(AAD_BIOMETRIC_PREFIX);
    out.extend_from_slice(vault_id);
    out
}

/// 启用生物识别解锁。
///
/// 必须在已经有 [`UnlockedVault`] 的状态下调 — 也就是说用户必须先用主密码正常解锁过一次。
pub fn enable_biometric_unlock(unlocked: &UnlockedVault) -> Result<BiometricUnlockSetup> {
    let wrapper_bytes: [u8; 32] = random::bytes::<32>()?;
    let wrapper_key = SymmetricKey::try_from_slice(&wrapper_bytes)?;
    let wrapped_kek = wrap_key(
        &wrapper_key,
        &unlocked.kek.0,
        &aad_for_biometric(&unlocked.vault_id),
    )?;
    Ok(BiometricUnlockSetup {
        wrapper_key: wrapper_bytes,
        envelope: BiometricEnvelope {
            version: KEYSET_FORMAT_VERSION,
            vault_id: unlocked.vault_id,
            wrapped_kek,
        },
    })
}

/// 用生物识别解锁。`wrapper_key` 来自 OS keychain,`envelope` 来自磁盘,`keyset` 是常规
/// EncryptedKeySet。任何环节失败都返回 [`CryptoError::DecryptFailed`]。
///
/// 注意:envelope.vault_id 与 keyset.vault_id 必须一致(防止张冠李戴 / 攻击者伪造 envelope)。
pub fn unlock_via_biometric(
    wrapper_key: &[u8; 32],
    envelope: &BiometricEnvelope,
    keyset: &EncryptedKeySet,
) -> Result<UnlockedVault> {
    if envelope.version != KEYSET_FORMAT_VERSION {
        return Err(CryptoError::UnsupportedVersion(envelope.version));
    }
    if envelope.vault_id != keyset.vault_id {
        return Err(CryptoError::DecryptFailed);
    }
    let wrapper_sym = SymmetricKey::try_from_slice(wrapper_key)?;
    let kek_inner = unwrap_key(
        &wrapper_sym,
        &envelope.wrapped_kek,
        &aad_for_biometric(&keyset.vault_id),
    )?;
    let kek = KeyEncryptionKey::from_symmetric(kek_inner);

    // KEK 拿到了,后面跟普通 unlock 走 KEK→VMK→IKEK 一路。
    let vmk_inner = unwrap_key(
        &kek.0,
        &keyset.wrapped_vmk,
        &aad_for_vmk(&keyset.account_id, &keyset.vault_id),
    )?;
    let vmk = VaultMasterKey::from_symmetric(vmk_inner);

    let ikek_inner = unwrap_key(
        &vmk.0,
        &keyset.wrapped_ikek,
        &aad_for_ikek(&keyset.vault_id),
    )?;
    let ikek = ItemKekKey::from_symmetric(ikek_inner);

    Ok(UnlockedVault {
        account_id: keyset.account_id,
        vault_id: keyset.vault_id,
        kek,
        vmk,
        ikek,
    })
}

// ---------- AAD 构造 ----------

const AAD_PREFIX: &[u8] = b"root-key";

pub(crate) fn aad_for_kek(account_id: &Id, vault_id: &Id, kdf: &KdfParams) -> Vec<u8> {
    let kdf_bytes = kdf.aad_bytes();
    let mut out = Vec::with_capacity(AAD_PREFIX.len() + 32 + 16 + 16 + kdf_bytes.len());
    out.extend_from_slice(AAD_PREFIX);
    out.extend_from_slice(b"/wrap-kek/v1/");
    out.extend_from_slice(account_id);
    out.extend_from_slice(vault_id);
    out.extend_from_slice(&kdf_bytes);
    out
}

pub(crate) fn aad_for_vmk(account_id: &Id, vault_id: &Id) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_PREFIX.len() + 32 + 16 + 16);
    out.extend_from_slice(AAD_PREFIX);
    out.extend_from_slice(b"/wrap-vmk/v1/");
    out.extend_from_slice(account_id);
    out.extend_from_slice(vault_id);
    out
}

pub(crate) fn aad_for_ikek(vault_id: &Id) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_PREFIX.len() + 24 + 16);
    out.extend_from_slice(AAD_PREFIX);
    out.extend_from_slice(b"/wrap-ikek/v1/");
    out.extend_from_slice(vault_id);
    out
}

pub(crate) fn aad_for_item_key(vault_id: &Id) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_PREFIX.len() + 32 + 16);
    out.extend_from_slice(AAD_PREFIX);
    out.extend_from_slice(b"/wrap-item-key/v1/");
    out.extend_from_slice(vault_id);
    out
}

pub(crate) fn aad_for_item_blob(vault_id: &Id) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_PREFIX.len() + 32 + 16);
    out.extend_from_slice(AAD_PREFIX);
    out.extend_from_slice(b"/item-blob/v1/");
    out.extend_from_slice(vault_id);
    out
}

fn aad_for_signing_seed(vault_id: &Id) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_PREFIX.len() + 32 + 16);
    out.extend_from_slice(AAD_PREFIX);
    out.extend_from_slice(b"/wrap-signing-seed/v1/");
    out.extend_from_slice(vault_id);
    out
}

/// 用 VMK 包装 Ed25519 signing-key 的 32 字节 seed,用于持久化到 `vault.json`。
///
/// AAD 绑定 vault_id 防止跨 vault 张冠李戴。专用 label `wrap-signing-seed/v1`
/// 防止与其他 wrap-* AEAD 上下文混淆。
pub fn wrap_signing_seed(
    unlocked: &UnlockedVault,
    seed: &[u8; 32],
) -> Result<crate::aead::WrappedKey> {
    let key = crate::keys::SymmetricKey::try_from_slice(seed)?;
    crate::aead::wrap_key(&unlocked.vmk.0, &key, &aad_for_signing_seed(&unlocked.vault_id))
}

/// 用 VMK 解开包装,返回 32 字节 signing seed。
pub fn unwrap_signing_seed(
    unlocked: &UnlockedVault,
    wrapped: &crate::aead::WrappedKey,
) -> Result<[u8; 32]> {
    let key = crate::aead::unwrap_key(
        &unlocked.vmk.0,
        wrapped,
        &aad_for_signing_seed(&unlocked.vault_id),
    )?;
    let mut out = [0u8; 32];
    out.copy_from_slice(key.expose_secret());
    Ok(out)
}

pub(crate) mod id_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 16], D::Error> {
        let v = <Vec<u8>>::deserialize(deserializer)?;
        if v.len() != 16 {
            return Err(serde::de::Error::custom("id must be 16 bytes"));
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_unlock_round_trip() {
        let created = create_vault_keys("hunter2").unwrap();
        let unlocked = unlock_vault("hunter2", &created.encrypted).unwrap();
        assert_eq!(
            unlocked.kek.expose_secret(),
            created.unlocked.kek.expose_secret()
        );
        assert_eq!(
            unlocked.vmk.expose_secret(),
            created.unlocked.vmk.expose_secret()
        );
        assert_eq!(
            unlocked.ikek.expose_secret(),
            created.unlocked.ikek.expose_secret()
        );
    }

    #[test]
    fn unlock_rejects_wrong_password() {
        let created = create_vault_keys("hunter2").unwrap();
        assert!(matches!(
            unlock_vault("hunter3", &created.encrypted),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn change_password_old_fails_new_succeeds() {
        let created = create_vault_keys("old").unwrap();
        let next = change_master_password("old", "new", &created.encrypted).unwrap();
        assert!(unlock_vault("old", &next).is_err());
        let unlocked = unlock_vault("new", &next).unwrap();
        // 同一 vault,KEK / VMK / IKEK 必须不变
        assert_eq!(
            unlocked.kek.expose_secret(),
            created.unlocked.kek.expose_secret()
        );
    }

    #[test]
    fn change_password_rotates_salt() {
        let created = create_vault_keys("old").unwrap();
        let next = change_master_password("old", "new", &created.encrypted).unwrap();
        assert_ne!(next.kdf.salt, created.encrypted.kdf.salt);
    }

    #[test]
    fn rotate_vault_key_invalidates_old_wrapped_vmk() {
        let created = create_vault_keys("pw").unwrap();
        let (next, next_unlocked) =
            rotate_vault_key(&created.unlocked, &created.encrypted).unwrap();

        assert_ne!(next.wrapped_vmk, created.encrypted.wrapped_vmk);
        let after = unlock_vault("pw", &next).unwrap();
        assert_eq!(after.vmk.expose_secret(), next_unlocked.vmk.expose_secret());
        assert_eq!(
            after.ikek.expose_secret(),
            created.unlocked.ikek.expose_secret()
        );
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut created = create_vault_keys("pw").unwrap();
        created.encrypted.version = 999;
        assert!(matches!(
            unlock_vault("pw", &created.encrypted),
            Err(CryptoError::UnsupportedVersion(999))
        ));
    }

    #[test]
    fn json_serialize_does_not_leak_keys() {
        let created = create_vault_keys("pw").unwrap();
        let json = serde_json::to_string(&created.encrypted).unwrap();
        let muk_secret = derive_muk("pw", &created.encrypted.kdf).unwrap();
        assert!(!json.contains(&hex16(&array_to_id(muk_secret.expose_secret()))));
        let kek_hex = bytes_to_hex(created.unlocked.kek.expose_secret());
        let vmk_hex = bytes_to_hex(created.unlocked.vmk.expose_secret());
        let ikek_hex = bytes_to_hex(created.unlocked.ikek.expose_secret());
        assert!(!json.contains(&kek_hex));
        assert!(!json.contains(&vmk_hex));
        assert!(!json.contains(&ikek_hex));

        let parsed: EncryptedKeySet = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, created.encrypted);
    }

    fn bytes_to_hex(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            s.push_str(&format!("{byte:02x}"));
        }
        s
    }

    fn array_to_id(a: &[u8; 32]) -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(&a[..16]);
        out
    }

    #[test]
    fn debug_does_not_leak_unlocked_keys() {
        let created = create_vault_keys("pw").unwrap();
        let s = format!("{:?}", created.unlocked);
        assert!(s.contains("REDACTED"));
        assert!(format!("{:?}", created.unlocked.kek).contains("REDACTED"));
        assert!(format!("{:?}", created.unlocked.vmk).contains("REDACTED"));
        assert!(format!("{:?}", created.unlocked.ikek).contains("REDACTED"));
    }

    #[test]
    fn biometric_enable_then_unlock_round_trip() {
        let created = create_vault_keys("hunter2").unwrap();
        let setup = enable_biometric_unlock(&created.unlocked).unwrap();
        let unlocked2 =
            unlock_via_biometric(&setup.wrapper_key, &setup.envelope, &created.encrypted).unwrap();
        assert_eq!(
            unlocked2.kek.expose_secret(),
            created.unlocked.kek.expose_secret()
        );
        assert_eq!(
            unlocked2.vmk.expose_secret(),
            created.unlocked.vmk.expose_secret()
        );
        assert_eq!(
            unlocked2.ikek.expose_secret(),
            created.unlocked.ikek.expose_secret()
        );
    }

    #[test]
    fn biometric_wrong_wrapper_fails() {
        let created = create_vault_keys("hunter2").unwrap();
        let setup = enable_biometric_unlock(&created.unlocked).unwrap();
        let mut wrong = setup.wrapper_key;
        wrong[0] ^= 0x01;
        assert!(matches!(
            unlock_via_biometric(&wrong, &setup.envelope, &created.encrypted),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn biometric_envelope_vault_id_must_match_keyset() {
        let created_a = create_vault_keys("hunter2").unwrap();
        let setup = enable_biometric_unlock(&created_a.unlocked).unwrap();
        let created_b = create_vault_keys("other").unwrap();
        assert!(matches!(
            unlock_via_biometric(&setup.wrapper_key, &setup.envelope, &created_b.encrypted),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn biometric_envelope_serializes() {
        let created = create_vault_keys("hunter2").unwrap();
        let setup = enable_biometric_unlock(&created.unlocked).unwrap();
        let s = serde_json::to_string(&setup.envelope).unwrap();
        let back: BiometricEnvelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back, setup.envelope);
    }

    /// envelope.version 与当前 KEYSET_FORMAT_VERSION 不一致 → 拒绝。
    #[test]
    fn biometric_rejects_envelope_with_future_version() {
        let created = create_vault_keys("pw").unwrap();
        let mut setup = enable_biometric_unlock(&created.unlocked).unwrap();
        setup.envelope.version = 999;
        let r = unlock_via_biometric(&setup.wrapper_key, &setup.envelope, &created.encrypted);
        assert!(matches!(r, Err(CryptoError::UnsupportedVersion(999))));
    }

    /// change_master_password 拒绝空新密码。
    #[test]
    fn change_password_rejects_empty_new() {
        let created = create_vault_keys("old").unwrap();
        let r = change_master_password("old", "", &created.encrypted);
        assert!(matches!(r, Err(CryptoError::InvalidArgument(_))));
    }

    /// change_master_password 旧密码错时直接走 unlock_vault 的 DecryptFailed。
    #[test]
    fn change_password_rejects_wrong_old() {
        let created = create_vault_keys("old").unwrap();
        let r = change_master_password("wrong-old", "new", &created.encrypted);
        assert!(matches!(r, Err(CryptoError::DecryptFailed)));
    }

    /// rotate_vault_key 拒绝 unlocked 与 keyset 的 id 不一致(防张冠李戴)。
    #[test]
    fn rotate_rejects_id_mismatch() {
        let a = create_vault_keys("a").unwrap();
        let b = create_vault_keys("b").unwrap();
        let r = rotate_vault_key(&a.unlocked, &b.encrypted);
        assert!(matches!(r, Err(CryptoError::InvalidArgument(_))));
    }

    /// id_bytes 反序列化:长度不为 16 的拒绝。
    #[test]
    fn keyset_rejects_bad_account_id_length() {
        let created = create_vault_keys("pw").unwrap();
        let mut v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&created.encrypted).unwrap()).unwrap();
        // 把 account_id 改成 15 字节
        v["account_id"] = serde_json::Value::Array(
            (0..15)
                .map(|_| serde_json::Value::Number(serde_json::Number::from(0)))
                .collect(),
        );
        let r: serde_json::Result<EncryptedKeySet> = serde_json::from_value(v);
        assert!(r.is_err());
    }
}
