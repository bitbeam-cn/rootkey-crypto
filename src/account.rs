//! ADR-010 账户层:一个主密码 → 多个逻辑 vault 的统一解锁。
//!
//! 在既有 per-vault 链 `MUK → KEK → VMK → IKEK → ItemKey` 之上插入账户层,
//! 插入点选在 **KEK**(而非 ADR 草稿中的 VMK)—— KEK 以下整条链与 item 加密
//! 格式零改动,旧 vault 迁移只需重新包装 KEK(与 VMK 的 AAD):
//!
//! ```text
//! Master Password(账户唯一)
//!         │  Argon2id
//!         ▼
//!     MUK ── wrap ──> ARK(Account Root Key,32B 随机)
//!                       ├── wrap ──> vault A 的 KEK ──> VMK ──> IKEK ──> ItemKey
//!                       ├── wrap ──> vault B 的 KEK ──> ...
//!                       └── (Phase B+)wrap ──> X25519/Ed25519 身份密钥(ADR-003 合流)
//! ```
//!
//! 引入 ARK(而非 MUK 直接包各 KEK)的原因:
//! - 换主密码 = 只重包 ARK 一条记录,vault 数量无关;
//! - 生物识别 = wrapper_key 只包 ARK 一条,同上;
//! - 已解锁会话内新建 vault 不需要重新输入主密码(ARK 在内存,直接 wrap 新 KEK)。
//!
//! 持久化分两块:
//! - [`AccountKeySet`](单文件,`identity.json` / 账户级 keyset bundle):KDF 参数 +
//!   wrapped ARK + 每 vault 一条 wrapped KEK;
//! - [`VaultKeySlot`](各 vault 目录内,替代旧 `EncryptedKeySet`):只剩 wrapped_vmk /
//!   wrapped_ikek(KEK 上移到账户层)。


use serde::{Deserialize, Serialize};

use crate::aead::{unwrap_key, wrap_key, WrappedKey};
use crate::error::{CryptoError, Result};
use crate::kdf::{derive_muk, KdfParams};
use crate::keys::{AccountRootKey, ItemKekKey, KeyEncryptionKey, SymmetricKey, VaultMasterKey};
use crate::random;
use crate::vault::{aad_for_ikek, aad_for_vmk, id_bytes, Id, UnlockedVault};

/// 当前 AccountKeySet / VaultKeySlot 的格式版本。
pub const ACCOUNT_FORMAT_VERSION: u16 = 1;

/// 账户持久化部分。**只**包含密文与公开参数,可放心写盘 / 进 keyset bundle 同步。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountKeySet {
    /// 格式版本。
    pub version: u16,
    /// 16 字节账户 ID。
    #[serde(with = "id_bytes")]
    pub account_id: Id,
    /// 账户创建时间(unix ms)。crypto 层不取时钟,由调用方(ffi_bridge)在
    /// 持久化前填充;试用计时等业务挂在它上面。
    #[serde(default)]
    pub created_at: i64,
    /// KDF 参数 + salt(账户唯一一份 —— 全账户只跑一次 Argon2id)。
    pub kdf: KdfParams,
    /// MUK 包装的 ARK。AAD 绑定 kdf 参数防降级。
    pub wrapped_ark: WrappedKey,
    /// 恢复密钥包装的 ARK(Apple 式 Recovery Key,ADR-010)。None = 未启用。
    /// 恢复密钥本体只显示一次、印进应急套件,系统不存明文。
    #[serde(default)]
    pub wrapped_ark_recovery: Option<WrappedKey>,
    /// 账户下每个 vault 一条:ARK 包装的该 vault KEK。
    pub vaults: Vec<AccountVaultEntry>,
}

/// 账户内单个 vault 的密钥挂载记录。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountVaultEntry {
    /// 16 字节 vault ID。
    #[serde(with = "id_bytes")]
    pub vault_id: Id,
    /// ARK 包装的该 vault KEK。
    pub wrapped_kek: WrappedKey,
}

/// vault 目录内的密钥残余(账户模型下替代旧 [`EncryptedKeySet`]):
/// KEK 上移到账户层后,vault 本地只剩 KEK 以下的两层包装。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultKeySlot {
    /// 格式版本。
    pub version: u16,
    /// 所属账户 ID(必须与 AccountKeySet.account_id 一致,防张冠李戴)。
    #[serde(with = "id_bytes")]
    pub account_id: Id,
    /// 16 字节 vault ID。
    #[serde(with = "id_bytes")]
    pub vault_id: Id,
    /// KEK 包装的 VMK。
    pub wrapped_vmk: WrappedKey,
    /// VMK 包装的 IKEK。
    pub wrapped_ikek: WrappedKey,
}

/// 解锁后的账户上下文。持有 ARK,`Drop` 时 zeroize。
///
/// 不预先解开各 vault —— 调用方按需对每个 vault 走
/// [`unlock_account_vault`](拿 [`UnlockedVault`])。
pub struct UnlockedAccount {
    /// 账户 ID。
    pub account_id: Id,
    pub(crate) ark: AccountRootKey,
}

impl core::fmt::Debug for UnlockedAccount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnlockedAccount")
            .field("account_id", &"[16B]")
            .field("ark", &"[REDACTED]")
            .finish()
    }
}

/// [`create_account`] 的返回:持久化部分 + 立即可用的解锁上下文。
pub struct AccountKeys {
    /// 持久化部分(尚无 vault,`vaults` 为空)。
    pub encrypted: AccountKeySet,
    /// 内存中已解开的账户上下文。
    pub unlocked: UnlockedAccount,
}

/// 新建 vault 在账户下的一次性产物。
pub struct VaultUnderAccount {
    /// 挂进 [`AccountKeySet::vaults`] 的记录。
    pub entry: AccountVaultEntry,
    /// 写进 vault 目录的密钥残余。
    pub slot: VaultKeySlot,
    /// 立即可用的解锁上下文。
    pub unlocked: UnlockedVault,
}

// ---------- AAD 构造 ----------

const AAD_PREFIX: &[u8] = b"root-key";

fn aad_for_ark(account_id: &Id, kdf: &KdfParams) -> Vec<u8> {
    let kdf_bytes = kdf.aad_bytes();
    let mut out = Vec::with_capacity(AAD_PREFIX.len() + 16 + 16 + kdf_bytes.len());
    out.extend_from_slice(AAD_PREFIX);
    out.extend_from_slice(b"/wrap-ark/v1/");
    out.extend_from_slice(account_id);
    out.extend_from_slice(&kdf_bytes);
    out
}

fn aad_for_vault_kek(account_id: &Id, vault_id: &Id) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_PREFIX.len() + 24 + 16 + 16);
    out.extend_from_slice(AAD_PREFIX);
    out.extend_from_slice(b"/wrap-vault-kek/v1/");
    out.extend_from_slice(account_id);
    out.extend_from_slice(vault_id);
    out
}

fn aad_for_account_biometric(account_id: &Id) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_PREFIX.len() + 24 + 16);
    out.extend_from_slice(AAD_PREFIX);
    out.extend_from_slice(b"/account-biometric/v1/");
    out.extend_from_slice(account_id);
    out
}

// ---------- 创建 / 解锁 ----------

/// 用主密码创建一个全新账户(尚无 vault)。
pub fn create_account(master_password: &str) -> Result<AccountKeys> {
    if master_password.is_empty() {
        return Err(CryptoError::InvalidArgument("master password is empty"));
    }
    let account_id: Id = random::bytes::<16>()?;
    let kdf = KdfParams::generate_default()?;
    let muk = derive_muk(master_password, &kdf)?;
    let ark = AccountRootKey::generate()?;
    let wrapped_ark = wrap_key(&muk.0, &ark.0, &aad_for_ark(&account_id, &kdf))?;
    Ok(AccountKeys {
        encrypted: AccountKeySet {
            version: ACCOUNT_FORMAT_VERSION,
            account_id,
            created_at: 0,
            kdf,
            wrapped_ark,
            wrapped_ark_recovery: None,
            vaults: Vec::new(),
        },
        unlocked: UnlockedAccount {
            account_id,
            ark,
        },
    })
}

/// 用主密码解锁账户(一次 Argon2id,解出 ARK;各 vault 再按需
/// [`unlock_account_vault`])。
///
/// 错误密码 / 篡改一律 [`CryptoError::DecryptFailed`],不区分原因。
pub fn unlock_account(master_password: &str, keyset: &AccountKeySet) -> Result<UnlockedAccount> {
    if keyset.version != ACCOUNT_FORMAT_VERSION {
        return Err(CryptoError::UnsupportedVersion(keyset.version));
    }
    keyset.kdf.validate()?;
    let muk = derive_muk(master_password, &keyset.kdf)?;
    let ark_inner = unwrap_key(
        &muk.0,
        &keyset.wrapped_ark,
        &aad_for_ark(&keyset.account_id, &keyset.kdf),
    )?;
    Ok(UnlockedAccount {
        account_id: keyset.account_id,
        ark: AccountRootKey::from_symmetric(ark_inner),
    })
}

/// 解锁账户下的单个 vault:ARK → KEK → VMK → IKEK。
pub fn unlock_account_vault(
    account: &UnlockedAccount,
    entry: &AccountVaultEntry,
    slot: &VaultKeySlot,
) -> Result<UnlockedVault> {
    if slot.version != ACCOUNT_FORMAT_VERSION {
        return Err(CryptoError::UnsupportedVersion(slot.version));
    }
    if slot.account_id != account.account_id || slot.vault_id != entry.vault_id {
        return Err(CryptoError::DecryptFailed);
    }
    let kek_inner = unwrap_key(
        &account.ark.0,
        &entry.wrapped_kek,
        &aad_for_vault_kek(&account.account_id, &entry.vault_id),
    )?;
    let kek = KeyEncryptionKey::from_symmetric(kek_inner);
    let vmk_inner = unwrap_key(
        &kek.0,
        &slot.wrapped_vmk,
        &aad_for_vmk(&account.account_id, &slot.vault_id),
    )?;
    let vmk = VaultMasterKey::from_symmetric(vmk_inner);
    let ikek_inner = unwrap_key(&vmk.0, &slot.wrapped_ikek, &aad_for_ikek(&slot.vault_id))?;
    Ok(UnlockedVault {
        account_id: account.account_id,
        vault_id: slot.vault_id,
        kek,
        vmk,
        ikek: ItemKekKey::from_symmetric(ikek_inner),
    })
}

/// 在已解锁账户下新建 vault(**不需要**主密码 —— ARK 在内存)。
///
/// 调用方把 `entry` push 进 [`AccountKeySet::vaults`] 并持久化,`slot` 写进
/// vault 目录。
pub fn create_vault_under_account(
    account: &UnlockedAccount,
) -> Result<VaultUnderAccount> {
    let vault_id: Id = random::bytes::<16>()?;
    let kek = KeyEncryptionKey::generate()?;
    let vmk = VaultMasterKey::generate()?;
    let ikek = ItemKekKey::generate()?;

    let wrapped_kek = wrap_key(
        &account.ark.0,
        &kek.0,
        &aad_for_vault_kek(&account.account_id, &vault_id),
    )?;
    let wrapped_vmk = wrap_key(&kek.0, &vmk.0, &aad_for_vmk(&account.account_id, &vault_id))?;
    let wrapped_ikek = wrap_key(&vmk.0, &ikek.0, &aad_for_ikek(&vault_id))?;

    Ok(VaultUnderAccount {
        entry: AccountVaultEntry {
            vault_id,
            wrapped_kek,
        },
        slot: VaultKeySlot {
            version: ACCOUNT_FORMAT_VERSION,
            account_id: account.account_id,
            vault_id,
            wrapped_vmk,
            wrapped_ikek,
        },
        unlocked: UnlockedVault {
            account_id: account.account_id,
            vault_id,
            kek,
            vmk,
            ikek,
        },
    })
}

/// 修改账户主密码:新 KDF salt + 新 MUK 重新包装 ARK。
///
/// vault 记录全部不变 —— vault 数量无关,O(1)。
pub fn change_account_password(
    old_password: &str,
    new_password: &str,
    current: &AccountKeySet,
) -> Result<AccountKeySet> {
    if new_password.is_empty() {
        return Err(CryptoError::InvalidArgument("new password is empty"));
    }
    let unlocked = unlock_account(old_password, current)?;
    let new_kdf = KdfParams::generate_default()?;
    let new_muk = derive_muk(new_password, &new_kdf)?;
    let wrapped_ark = wrap_key(
        &new_muk.0,
        &unlocked.ark.0,
        &aad_for_ark(&current.account_id, &new_kdf),
    )?;
    Ok(AccountKeySet {
        version: current.version,
        account_id: current.account_id,
        created_at: current.created_at,
        kdf: new_kdf,
        wrapped_ark,
        wrapped_ark_recovery: current.wrapped_ark_recovery.clone(),
        vaults: current.vaults.clone(),
    })
}

// ---------- 恢复密钥(Apple 式 Recovery Key)----------

/// Crockford base32 字符集(去 I/L/O/U 歧义字符)。
const RECOVERY_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// 5 组 × 5 字符 = 25 字符 × 5bit = 125 bit 熵 —— 不可爆破,无需慢 KDF。
const RECOVERY_GROUPS: usize = 5;
const RECOVERY_GROUP_LEN: usize = 5;

fn recovery_kek_from(normalized: &str, account_id: &Id) -> Result<SymmetricKey> {
    // blake3 derive_key:context 绑定用途,输入绑定 account_id 防跨账户重放。
    let mut material = Vec::with_capacity(normalized.len() + 16);
    material.extend_from_slice(normalized.as_bytes());
    material.extend_from_slice(account_id);
    let key = blake3::derive_key("root-key/recovery-key/v1", &material);
    SymmetricKey::try_from_slice(&key)
}

/// 规范化用户输入:大写、去空白与连字符、去可选 RK 前缀;校验字符集与长度。
fn normalize_recovery_key(input: &str) -> Result<String> {
    let mut up: String = input
        .trim()
        .to_ascii_uppercase()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    if let Some(rest) = up.strip_prefix("RK") {
        up = rest.to_string();
    }
    if up.len() != RECOVERY_GROUPS * RECOVERY_GROUP_LEN
        || !up.bytes().all(|b| RECOVERY_ALPHABET.contains(&b))
    {
        return Err(CryptoError::InvalidArgument("malformed recovery key"));
    }
    Ok(up)
}

fn format_recovery_key(raw: &str) -> String {
    let groups: Vec<&str> = raw
        .as_bytes()
        .chunks(RECOVERY_GROUP_LEN)
        .map(|c| core::str::from_utf8(c).expect("ascii"))
        .collect();
    format!("RK-{}", groups.join("-"))
}

/// 生成新恢复密钥并用它包装 ARK。返回(展示串,包装密文)。
///
/// 调用方把 `wrapped` 写进 [`AccountKeySet::wrapped_ark_recovery`] 并持久化;
/// **展示串只在此刻存在一次**,用户抄写/打印后系统不再保有。重复调用 = 旋转
/// (旧恢复密钥随包装被覆盖而作废)。
pub fn setup_recovery_key(account: &UnlockedAccount) -> Result<(String, WrappedKey)> {
    let mut raw = String::with_capacity(RECOVERY_GROUPS * RECOVERY_GROUP_LEN);
    for _ in 0..(RECOVERY_GROUPS * RECOVERY_GROUP_LEN) {
        let b: [u8; 1] = random::bytes::<1>()?;
        raw.push(RECOVERY_ALPHABET[(b[0] & 0x1F) as usize] as char);
    }
    let kek = recovery_kek_from(&raw, &account.account_id)?;
    let wrapped = wrap_key(
        &kek,
        &account.ark.0,
        &aad_for_recovery(&account.account_id),
    )?;
    Ok((format_recovery_key(&raw), wrapped))
}

/// 用恢复密钥解锁账户(忘记主密码时的恢复路径)。
pub fn unlock_account_with_recovery_key(
    recovery_key: &str,
    keyset: &AccountKeySet,
) -> Result<UnlockedAccount> {
    if keyset.version != ACCOUNT_FORMAT_VERSION {
        return Err(CryptoError::UnsupportedVersion(keyset.version));
    }
    let wrapped = keyset
        .wrapped_ark_recovery
        .as_ref()
        .ok_or(CryptoError::InvalidArgument("recovery key not set up"))?;
    let raw = normalize_recovery_key(recovery_key)?;
    let kek = recovery_kek_from(&raw, &keyset.account_id)?;
    let ark_inner = unwrap_key(&kek, wrapped, &aad_for_recovery(&keyset.account_id))?;
    Ok(UnlockedAccount {
        account_id: keyset.account_id,
        ark: AccountRootKey::from_symmetric(ark_inner),
    })
}

/// 忘记主密码:凭恢复密钥重设主密码(数据全量保留)。
///
/// 新 KDF salt + 新 MUK 重新包装 ARK;恢复密钥包装保持不变(密钥未泄露
/// 无需旋转;要旋转走 [`setup_recovery_key`])。
pub fn reset_password_with_recovery_key(
    recovery_key: &str,
    new_password: &str,
    current: &AccountKeySet,
) -> Result<AccountKeySet> {
    if new_password.is_empty() {
        return Err(CryptoError::InvalidArgument("new password is empty"));
    }
    let unlocked = unlock_account_with_recovery_key(recovery_key, current)?;
    let new_kdf = KdfParams::generate_default()?;
    let new_muk = derive_muk(new_password, &new_kdf)?;
    let wrapped_ark = wrap_key(
        &new_muk.0,
        &unlocked.ark.0,
        &aad_for_ark(&current.account_id, &new_kdf),
    )?;
    Ok(AccountKeySet {
        version: current.version,
        account_id: current.account_id,
        created_at: current.created_at,
        kdf: new_kdf,
        wrapped_ark,
        wrapped_ark_recovery: current.wrapped_ark_recovery.clone(),
        vaults: current.vaults.clone(),
    })
}

fn aad_for_recovery(account_id: &Id) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_PREFIX.len() + 24 + 16);
    out.extend_from_slice(AAD_PREFIX);
    out.extend_from_slice(b"/wrap-ark-recovery/v1/");
    out.extend_from_slice(account_id);
    out
}

// ---------- 生物识别(账户级)----------

/// 账户级生物识别信封:wrapper_key(OS keychain)包装 ARK,一条记录覆盖全部 vault。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountBiometricEnvelope {
    /// 格式版本。
    pub version: u16,
    /// 关联账户 ID。
    #[serde(with = "id_bytes")]
    pub account_id: Id,
    /// wrapper_key 包装的 ARK。
    pub wrapped_ark: WrappedKey,
}

/// [`enable_account_biometric`] 的返回。`wrapper_key` 必须存 OS keychain
/// (生物识别保护),`envelope` 落盘。
pub struct AccountBiometricSetup {
    /// 32 字节随机 wrapper_key。
    pub wrapper_key: [u8; 32],
    /// 持久化信封。
    pub envelope: AccountBiometricEnvelope,
}

/// 启用账户级生物识别解锁(须已用主密码解锁过)。
pub fn enable_account_biometric(account: &UnlockedAccount) -> Result<AccountBiometricSetup> {
    let wrapper_bytes: [u8; 32] = random::bytes::<32>()?;
    let wrapper_key = SymmetricKey::try_from_slice(&wrapper_bytes)?;
    let wrapped_ark = wrap_key(
        &wrapper_key,
        &account.ark.0,
        &aad_for_account_biometric(&account.account_id),
    )?;
    Ok(AccountBiometricSetup {
        wrapper_key: wrapper_bytes,
        envelope: AccountBiometricEnvelope {
            version: ACCOUNT_FORMAT_VERSION,
            account_id: account.account_id,
            wrapped_ark,
        },
    })
}

/// 用生物识别解锁账户(绕过 Argon2id,直接解出 ARK)。
pub fn unlock_account_via_biometric(
    wrapper_key: &[u8; 32],
    envelope: &AccountBiometricEnvelope,
    keyset: &AccountKeySet,
) -> Result<UnlockedAccount> {
    if envelope.version != ACCOUNT_FORMAT_VERSION {
        return Err(CryptoError::UnsupportedVersion(envelope.version));
    }
    if envelope.account_id != keyset.account_id {
        return Err(CryptoError::DecryptFailed);
    }
    let wrapper_sym = SymmetricKey::try_from_slice(wrapper_key)?;
    let ark_inner = unwrap_key(
        &wrapper_sym,
        &envelope.wrapped_ark,
        &aad_for_account_biometric(&keyset.account_id),
    )?;
    Ok(UnlockedAccount {
        account_id: keyset.account_id,
        ark: AccountRootKey::from_symmetric(ark_inner),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{decrypt_item, encrypt_item};
    use crate::vault::create_vault_keys;

    #[test]
    fn create_then_unlock_round_trip() {
        let acc = create_account("hunter2").unwrap();
        let unlocked = unlock_account("hunter2", &acc.encrypted).unwrap();
        assert_eq!(
            unlocked.ark.expose_secret(),
            acc.unlocked.ark.expose_secret()
        );
    }

    #[test]
    fn unlock_rejects_wrong_password() {
        let acc = create_account("hunter2").unwrap();
        assert!(matches!(
            unlock_account("hunter3", &acc.encrypted),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn create_account_rejects_empty_password() {
        assert!(matches!(
            create_account(""),
            Err(CryptoError::InvalidArgument(_))
        ));
    }

    #[test]
    fn multi_vault_one_unlock_opens_all() {
        let acc = create_account("pw").unwrap();
        let a = create_vault_under_account(&acc.unlocked).unwrap();
        let b = create_vault_under_account(&acc.unlocked).unwrap();
        assert_ne!(a.slot.vault_id, b.slot.vault_id);
        assert_ne!(
            a.unlocked.ikek.expose_secret(),
            b.unlocked.ikek.expose_secret()
        );

        // 一次解锁 → 两个 vault 都能打开
        let session = unlock_account("pw", &acc.encrypted).unwrap();
        let ua = unlock_account_vault(&session, &a.entry, &a.slot).unwrap();
        let ub = unlock_account_vault(&session, &b.entry, &b.slot).unwrap();
        assert_eq!(ua.ikek.expose_secret(), a.unlocked.ikek.expose_secret());
        assert_eq!(ub.ikek.expose_secret(), b.unlocked.ikek.expose_secret());
    }

    #[test]
    fn vault_entries_are_not_interchangeable() {
        // 张冠李戴:vault A 的 entry 配 vault B 的 slot 必须失败
        let acc = create_account("pw").unwrap();
        let a = create_vault_under_account(&acc.unlocked).unwrap();
        let b = create_vault_under_account(&acc.unlocked).unwrap();
        assert!(unlock_account_vault(&acc.unlocked, &a.entry, &b.slot).is_err());
        // 换 wrapped_kek 内容也失败(AAD 绑定 vault_id)
        let mut forged = a.entry.clone();
        forged.wrapped_kek = b.entry.wrapped_kek.clone();
        assert!(unlock_account_vault(&acc.unlocked, &forged, &a.slot).is_err());
    }

    #[test]
    fn slot_from_other_account_rejected() {
        let acc1 = create_account("pw1").unwrap();
        let acc2 = create_account("pw2").unwrap();
        let v = create_vault_under_account(&acc1.unlocked).unwrap();
        assert!(matches!(
            unlock_account_vault(&acc2.unlocked, &v.entry, &v.slot),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn change_password_old_fails_new_succeeds_vaults_survive() {
        let acc = create_account("old").unwrap();
        let v = create_vault_under_account(&acc.unlocked).unwrap();
        let mut keyset = acc.encrypted.clone();
        keyset.vaults.push(v.entry.clone());

        let next = change_account_password("old", "new", &keyset).unwrap();
        assert!(unlock_account("old", &next).is_err());
        let session = unlock_account("new", &next).unwrap();
        // ARK 不变、vault 记录不变 → vault 照常打开
        let unlocked = unlock_account_vault(&session, &next.vaults[0], &v.slot).unwrap();
        assert_eq!(
            unlocked.ikek.expose_secret(),
            v.unlocked.ikek.expose_secret()
        );
        assert_ne!(next.kdf.salt, keyset.kdf.salt);
    }

    #[test]
    fn rejects_unsupported_version() {
        let acc = create_account("pw").unwrap();
        let mut bad = acc.encrypted.clone();
        bad.version = 999;
        assert!(matches!(
            unlock_account("pw", &bad),
            Err(CryptoError::UnsupportedVersion(999))
        ));

        let v = create_vault_under_account(&acc.unlocked).unwrap();
        let mut bad_slot = v.slot.clone();
        bad_slot.version = 999;
        assert!(matches!(
            unlock_account_vault(&acc.unlocked, &v.entry, &bad_slot),
            Err(CryptoError::UnsupportedVersion(999))
        ));
    }

    #[test]
    fn json_round_trips_and_does_not_leak_keys() {
        let acc = create_account("pw").unwrap();
        let v = create_vault_under_account(&acc.unlocked).unwrap();
        let mut keyset = acc.encrypted.clone();
        keyset.vaults.push(v.entry.clone());

        let json = serde_json::to_string(&keyset).unwrap();
        let ark_hex = hex(acc.unlocked.ark.expose_secret());
        let kek_hex = hex(v.unlocked.kek.expose_secret());
        assert!(!json.contains(&ark_hex));
        assert!(!json.contains(&kek_hex));
        let parsed: AccountKeySet = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, keyset);

        let slot_json = serde_json::to_string(&v.slot).unwrap();
        let back: VaultKeySlot = serde_json::from_str(&slot_json).unwrap();
        assert_eq!(back, v.slot);
    }

    #[test]
    fn debug_does_not_leak() {
        let acc = create_account("pw").unwrap();
        assert!(format!("{:?}", acc.unlocked).contains("REDACTED"));
    }

    #[test]
    fn biometric_round_trip_and_wrong_wrapper_fails() {
        let acc = create_account("pw").unwrap();
        let v = create_vault_under_account(&acc.unlocked).unwrap();
        let setup = enable_account_biometric(&acc.unlocked).unwrap();

        let session =
            unlock_account_via_biometric(&setup.wrapper_key, &setup.envelope, &acc.encrypted)
                .unwrap();
        let unlocked = unlock_account_vault(&session, &v.entry, &v.slot).unwrap();
        assert_eq!(
            unlocked.ikek.expose_secret(),
            v.unlocked.ikek.expose_secret()
        );

        let mut wrong = setup.wrapper_key;
        wrong[0] ^= 0x01;
        assert!(matches!(
            unlock_account_via_biometric(&wrong, &setup.envelope, &acc.encrypted),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn biometric_envelope_account_id_must_match() {
        let acc1 = create_account("pw1").unwrap();
        let acc2 = create_account("pw2").unwrap();
        let setup = enable_account_biometric(&acc1.unlocked).unwrap();
        assert!(matches!(
            unlock_account_via_biometric(&setup.wrapper_key, &setup.envelope, &acc2.encrypted),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn recovery_key_roundtrip_and_reset_password() {
        let acc = create_account("old-pw").unwrap();
        let v = create_vault_under_account(&acc.unlocked).unwrap();
        let mut keyset = acc.encrypted.clone();
        keyset.vaults.push(v.entry.clone());
        let (display, wrapped) = setup_recovery_key(&acc.unlocked).unwrap();
        keyset.wrapped_ark_recovery = Some(wrapped);

        // 展示串格式:RK-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
        assert!(display.starts_with("RK-"));
        assert_eq!(display.len(), 3 + 5 * 5 + 4);

        // 恢复密钥直接解锁(容忍小写/去分隔输入)
        let messy = display.to_ascii_lowercase().replace('-', " ");
        let session = unlock_account_with_recovery_key(&messy, &keyset).unwrap();
        let unlocked = unlock_account_vault(&session, &keyset.vaults[0], &v.slot).unwrap();
        assert_eq!(unlocked.ikek.expose_secret(), v.unlocked.ikek.expose_secret());

        // 凭恢复密钥重设主密码:旧密码失效、新密码可用、vault 原样
        let next = reset_password_with_recovery_key(&display, "new-pw", &keyset).unwrap();
        assert!(unlock_account("old-pw", &next).is_err());
        let s2 = unlock_account("new-pw", &next).unwrap();
        let u2 = unlock_account_vault(&s2, &next.vaults[0], &v.slot).unwrap();
        assert_eq!(u2.ikek.expose_secret(), v.unlocked.ikek.expose_secret());
        // 恢复密钥依旧有效
        unlock_account_with_recovery_key(&display, &next).unwrap();
    }

    #[test]
    fn recovery_key_wrong_or_absent_fails() {
        let acc = create_account("pw").unwrap();
        let mut keyset = acc.encrypted.clone();
        assert!(matches!(
            unlock_account_with_recovery_key("RK-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA", &keyset),
            Err(CryptoError::InvalidArgument(_))
        ));
        let (display, wrapped) = setup_recovery_key(&acc.unlocked).unwrap();
        keyset.wrapped_ark_recovery = Some(wrapped);
        let mut bad = display.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == 'A' { 'B' } else { 'A' });
        assert!(unlock_account_with_recovery_key(&bad, &keyset).is_err());
        assert!(matches!(
            unlock_account_with_recovery_key("too-short", &keyset),
            Err(CryptoError::InvalidArgument(_))
        ));
    }

    #[test]
    fn recovery_key_rotation_invalidates_old() {
        let acc = create_account("pw").unwrap();
        let mut keyset = acc.encrypted.clone();
        let (old_display, wrapped1) = setup_recovery_key(&acc.unlocked).unwrap();
        keyset.wrapped_ark_recovery = Some(wrapped1);
        let (new_display, wrapped2) = setup_recovery_key(&acc.unlocked).unwrap();
        keyset.wrapped_ark_recovery = Some(wrapped2);
        assert!(unlock_account_with_recovery_key(&old_display, &keyset).is_err());
        unlock_account_with_recovery_key(&new_display, &keyset).unwrap();
    }

    fn hex(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            s.push_str(&format!("{byte:02x}"));
        }
        s
    }
}
