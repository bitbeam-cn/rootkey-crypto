//! Item 加密 / 解密。
//!
//! 每条 item 的加密分两步:
//! 1. 生成一把全新随机 [`ItemKey`],用 IKEK 通过 AES-256-GCM-SIV 包装
//! 2. 用 ItemKey 通过 XChaCha20-Poly1305 加密 payload
//!
//! 持久化时,wrapped_item_key 与 ciphertext 一起存。解密时反向执行:用 IKEK 解出
//! ItemKey,再用 ItemKey 解 ciphertext。
//!
//! payload 通常是序列化好的 item 结构(JSON / CBOR),由调用方负责。

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::aead::{open_blob, seal_blob, unwrap_key, wrap_key, SealedBlob, WrappedKey};
use crate::error::Result;
use crate::keys::ItemKey;
use crate::vault::{aad_for_item_blob, aad_for_item_key, UnlockedVault};

/// item 封装格式版本 —— 与密钥集格式版本([`KEYSET_FORMAT_VERSION`](crate::vault::KEYSET_FORMAT_VERSION))
/// **独立演进**。item 数据封装(wrapped_item_key + blob + AAD 结构)变更升本轴,
/// 不必连累密钥层格式;反之亦然。
/// - v2:AES-256-GCM-SIV 包裹 ItemKey。
/// - v3:AAD 纳入 item_id —— 把单条 item 的密码学身份锚进 AEAD,同步层不能再
///   把一条 item 的密文换位/回滚/复制到另一条(否则 AAD 不匹配、解密失败)。
pub const ITEM_FORMAT_VERSION: u16 = 3;

/// 能读到多老的 item 封装格式。**提高它之前必须先写好迁移**。
pub const ITEM_MIN_READABLE_VERSION: u16 = 3;

/// 持久化的单条 item 密文。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedItemBlob {
    /// item 封装格式版本([`ITEM_FORMAT_VERSION`])。
    pub version: u16,
    /// 用 IKEK 包装的 ItemKey。
    pub wrapped_item_key: WrappedKey,
    /// 用 ItemKey 加密的 payload。
    pub blob: SealedBlob,
}

/// 加密一条 item。
///
/// `plaintext` 是任意字节(通常是 JSON / CBOR 序列化结果)。
/// 返回的 [`EncryptedItemBlob`] 可以序列化、写盘、同步,**不**包含任何明文密钥。
///
/// 注意:本函数会**生成全新随机 ItemKey**,因此同一明文连续两次加密的密文必然不同。
/// `item_id` 是该 item 的 16 字节稳定身份(UUID)。它进 AAD,把密文与身份绑死;
/// 解密时必须由**可信来源**(item 的存储位置 / manifest 索引)提供同一个 id,
/// 否则解密失败。manifest 这类非 item 用保留 sentinel(全零,非合法 UUIDv4)。
pub fn encrypt_item(
    plaintext: &[u8],
    item_id: &[u8; 16],
    vault: &UnlockedVault,
) -> Result<EncryptedItemBlob> {
    let item_key = ItemKey::generate()?;

    let wrapped_item_key = wrap_key(
        &vault.ikek.0,
        &item_key.0,
        &aad_for_item_key(&vault.vault_id, item_id),
    )?;

    let blob = seal_blob(
        &item_key.0,
        plaintext,
        &aad_for_item_blob(&vault.vault_id, item_id),
    )?;

    Ok(EncryptedItemBlob {
        version: ITEM_FORMAT_VERSION,
        wrapped_item_key,
        blob,
    })
}

/// 解密一条 item,返回 zeroize 包装的明文。
///
/// 任何步骤失败(密文损坏、AAD 不匹配、wrap 损坏)都返回 [`crate::CryptoError::DecryptFailed`],
/// 不区分原因。
pub fn decrypt_item(
    encrypted: &EncryptedItemBlob,
    item_id: &[u8; 16],
    vault: &UnlockedVault,
) -> Result<Zeroizing<Vec<u8>>> {
    if encrypted.version > ITEM_FORMAT_VERSION {
        return Err(crate::CryptoError::UnsupportedVersion(encrypted.version));
    }
    if encrypted.version < ITEM_MIN_READABLE_VERSION {
        return Err(crate::CryptoError::SchemaTooOld(encrypted.version));
    }

    let item_key_inner = unwrap_key(
        &vault.ikek.0,
        &encrypted.wrapped_item_key,
        &aad_for_item_key(&vault.vault_id, item_id),
    )?;
    let item_key = ItemKey::from_symmetric(item_key_inner);

    open_blob(
        &item_key.0,
        &encrypted.blob,
        &aad_for_item_blob(&vault.vault_id, item_id),
    )
}

/// IKEK 旋转时,把一条 item 的 `wrapped_item_key` 从旧 IKEK 重包到新 IKEK。
///
/// ItemKey 值不变,`blob`(ItemKey 加密的 payload)原样保留 —— 只换外层包裹。
/// `old_vault` 持旧 IKEK、`new_vault` 持新 IKEK([`crate::vault::rotate_ikek`] 产出);
/// 两者 `vault_id` 必须相同、`item_id` 与原加密时一致(AAD 绑定 vault_id + item_id)。
pub fn rewrap_item_key(
    old_vault: &UnlockedVault,
    new_vault: &UnlockedVault,
    encrypted: &EncryptedItemBlob,
    item_id: &[u8; 16],
) -> Result<EncryptedItemBlob> {
    if encrypted.version > ITEM_FORMAT_VERSION {
        return Err(crate::CryptoError::UnsupportedVersion(encrypted.version));
    }
    if encrypted.version < ITEM_MIN_READABLE_VERSION {
        return Err(crate::CryptoError::SchemaTooOld(encrypted.version));
    }
    // 旧 IKEK 解出 ItemKey
    let item_key = unwrap_key(
        &old_vault.ikek.0,
        &encrypted.wrapped_item_key,
        &aad_for_item_key(&old_vault.vault_id, item_id),
    )?;
    // 新 IKEK 重包(AAD 不变:vault_id + item_id 相同)
    let wrapped_item_key = wrap_key(
        &new_vault.ikek.0,
        &item_key,
        &aad_for_item_key(&new_vault.vault_id, item_id),
    )?;
    Ok(EncryptedItemBlob {
        version: ITEM_FORMAT_VERSION,
        wrapped_item_key,
        blob: encrypted.blob.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::create_vault_keys;

    fn fresh_vault() -> UnlockedVault {
        create_vault_keys("pw").unwrap().unlocked
    }
    const ID_A: [u8; 16] = [0x11; 16];
    const ID_B: [u8; 16] = [0x22; 16];

    #[test]
    fn encrypt_then_decrypt_round_trip() {
        let vault = fresh_vault();
        let plaintext = b"login: alice / password: hunter2";
        let blob = encrypt_item(plaintext, &ID_A, &vault).unwrap();
        let decrypted = decrypt_item(&blob, &ID_A, &vault).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    /// 核心新属性:同 vault、同密文,拿另一条 item 的 id 解密必须失败
    /// (同步层不能把 item A 的密文换位/回滚到 item B)。
    #[test]
    fn wrong_item_id_rejected() {
        let vault = fresh_vault();
        let blob = encrypt_item(b"secret", &ID_A, &vault).unwrap();
        assert!(decrypt_item(&blob, &ID_A, &vault).is_ok());
        assert!(decrypt_item(&blob, &ID_B, &vault).is_err());
    }

    #[test]
    fn same_plaintext_two_encrypts_have_distinct_ciphertexts() {
        let vault = fresh_vault();
        let p = b"identical";
        let a = encrypt_item(p, &ID_A, &vault).unwrap();
        let b = encrypt_item(p, &ID_A, &vault).unwrap();
        assert_ne!(a.blob.nonce, b.blob.nonce);
        assert_ne!(a.blob.ciphertext, b.blob.ciphertext);
        assert_ne!(a.wrapped_item_key.nonce, b.wrapped_item_key.nonce);
        assert_ne!(a.wrapped_item_key.ciphertext, b.wrapped_item_key.ciphertext);
    }

    #[test]
    fn tampering_payload_ciphertext_fails() {
        let vault = fresh_vault();
        let mut blob = encrypt_item(b"hello", &ID_A, &vault).unwrap();
        blob.blob.ciphertext[0] ^= 0x01;
        assert!(decrypt_item(&blob, &ID_A, &vault).is_err());
    }

    #[test]
    fn tampering_payload_nonce_fails() {
        let vault = fresh_vault();
        let mut blob = encrypt_item(b"hello", &ID_A, &vault).unwrap();
        blob.blob.nonce[0] ^= 0x01;
        assert!(decrypt_item(&blob, &ID_A, &vault).is_err());
    }

    #[test]
    fn tampering_wrapped_item_key_fails() {
        let vault = fresh_vault();
        let mut blob = encrypt_item(b"hello", &ID_A, &vault).unwrap();
        blob.wrapped_item_key.ciphertext[0] ^= 0x01;
        assert!(decrypt_item(&blob, &ID_A, &vault).is_err());
    }

    #[test]
    fn item_does_not_decrypt_under_different_vault() {
        let v1 = fresh_vault();
        let v2 = fresh_vault();
        let blob = encrypt_item(b"hello", &ID_A, &v1).unwrap();
        assert!(decrypt_item(&blob, &ID_A, &v2).is_err());
    }

    #[test]
    fn json_blob_does_not_contain_plaintext() {
        let vault = fresh_vault();
        let plaintext = b"super-secret-password-DO-NOT-LEAK";
        let blob = encrypt_item(plaintext, &ID_A, &vault).unwrap();
        let json = serde_json::to_string(&blob).unwrap();
        // 明文 ASCII 不应出现在 JSON
        assert!(!json.contains("super-secret-password"));
        assert!(!json.contains("DO-NOT-LEAK"));
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let vault = fresh_vault();
        let blob = encrypt_item(b"", &ID_A, &vault).unwrap();
        let decrypted = decrypt_item(&blob, &ID_A, &vault).unwrap();
        assert!(decrypted.is_empty());
    }

    /// 持久化 blob 的 version 字段被改成非当前版本 → 拒绝。
    #[test]
    fn decrypt_rejects_unsupported_version() {
        let vault = fresh_vault();
        let mut blob = encrypt_item(b"hi", &ID_A, &vault).unwrap();
        blob.version = 999;
        let r = decrypt_item(&blob, &ID_A, &vault);
        assert!(matches!(r, Err(crate::CryptoError::UnsupportedVersion(999))));
    }

    /// 加密后 JSON round-trip:磁盘上落下来再读回应当还能解密。
    #[test]
    fn blob_json_round_trip_still_decrypts() {
        let vault = fresh_vault();
        let blob = encrypt_item(b"persistent", &ID_A, &vault).unwrap();
        let s = serde_json::to_string(&blob).unwrap();
        let back: EncryptedItemBlob = serde_json::from_str(&s).unwrap();
        let pt = decrypt_item(&back, &ID_A, &vault).unwrap();
        assert_eq!(pt.as_slice(), b"persistent");
    }

    /// IKEK 旋转 + 逐条重包:新 IKEK 下能解、blob 未变、旧包裹在新 IKEK 下失效。
    #[test]
    fn rotate_ikek_and_rewrap_item_key() {
        use crate::vault::{create_vault_keys, rotate_ikek};
        let created = create_vault_keys("pw").unwrap();
        let blob = encrypt_item(b"secret payload", &ID_A, &created.unlocked).unwrap();

        // 旋转 IKEK
        let (_next_keyset, new_unlocked) =
            rotate_ikek(&created.unlocked, &created.encrypted).unwrap();

        // 旧 wrapped_item_key 在新 IKEK 下解不开
        assert!(decrypt_item(&blob, &ID_A, &new_unlocked).is_err());

        // 重包后:新 IKEK 下能解出同一 payload,且 blob(payload 密文)未变
        let rewrapped = rewrap_item_key(&created.unlocked, &new_unlocked, &blob, &ID_A).unwrap();
        assert_eq!(rewrapped.blob, blob.blob, "payload 密文不应改变");
        assert_ne!(
            rewrapped.wrapped_item_key, blob.wrapped_item_key,
            "wrapped_item_key 应换新 IKEK 包裹"
        );
        let pt = decrypt_item(&rewrapped, &ID_A, &new_unlocked).unwrap();
        assert_eq!(pt.as_slice(), b"secret payload");

        // 重包时 item_id 必须一致:换 id 重包会导致解密时 AAD 不符
        let rewrapped_wrong = rewrap_item_key(&created.unlocked, &new_unlocked, &blob, &ID_A).unwrap();
        assert!(decrypt_item(&rewrapped_wrong, &ID_B, &new_unlocked).is_err());
    }

    /// 大 payload(1 MiB)亦能 round-trip。
    #[test]
    fn large_payload_round_trips() {
        let vault = fresh_vault();
        let big = vec![0x42u8; 1024 * 1024];
        let blob = encrypt_item(&big, &ID_A, &vault).unwrap();
        let pt = decrypt_item(&blob, &ID_A, &vault).unwrap();
        assert_eq!(pt.as_slice(), big.as_slice());
    }
}
