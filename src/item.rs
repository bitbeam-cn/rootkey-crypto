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
use crate::vault::{aad_for_item_blob, aad_for_item_key, UnlockedVault, KEYSET_FORMAT_VERSION};

/// 持久化的单条 item 密文。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedItemBlob {
    /// 与 [`EncryptedKeySet::version`](crate::vault::EncryptedKeySet::version) 一致。
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
pub fn encrypt_item(plaintext: &[u8], vault: &UnlockedVault) -> Result<EncryptedItemBlob> {
    let item_key = ItemKey::generate()?;

    let wrapped_item_key = wrap_key(
        &vault.ikek.0,
        &item_key.0,
        &aad_for_item_key(&vault.vault_id),
    )?;

    let blob = seal_blob(&item_key.0, plaintext, &aad_for_item_blob(&vault.vault_id))?;

    Ok(EncryptedItemBlob {
        version: KEYSET_FORMAT_VERSION,
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
    vault: &UnlockedVault,
) -> Result<Zeroizing<Vec<u8>>> {
    if encrypted.version != KEYSET_FORMAT_VERSION {
        return Err(crate::CryptoError::UnsupportedVersion(encrypted.version));
    }

    let item_key_inner = unwrap_key(
        &vault.ikek.0,
        &encrypted.wrapped_item_key,
        &aad_for_item_key(&vault.vault_id),
    )?;
    let item_key = ItemKey::from_symmetric(item_key_inner);

    open_blob(
        &item_key.0,
        &encrypted.blob,
        &aad_for_item_blob(&vault.vault_id),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::create_vault_keys;

    fn fresh_vault() -> UnlockedVault {
        create_vault_keys("pw").unwrap().unlocked
    }

    #[test]
    fn encrypt_then_decrypt_round_trip() {
        let vault = fresh_vault();
        let plaintext = b"login: alice / password: hunter2";
        let blob = encrypt_item(plaintext, &vault).unwrap();
        let decrypted = decrypt_item(&blob, &vault).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn same_plaintext_two_encrypts_have_distinct_ciphertexts() {
        let vault = fresh_vault();
        let p = b"identical";
        let a = encrypt_item(p, &vault).unwrap();
        let b = encrypt_item(p, &vault).unwrap();
        assert_ne!(a.blob.nonce, b.blob.nonce);
        assert_ne!(a.blob.ciphertext, b.blob.ciphertext);
        assert_ne!(a.wrapped_item_key.nonce, b.wrapped_item_key.nonce);
        assert_ne!(a.wrapped_item_key.ciphertext, b.wrapped_item_key.ciphertext);
    }

    #[test]
    fn tampering_payload_ciphertext_fails() {
        let vault = fresh_vault();
        let mut blob = encrypt_item(b"hello", &vault).unwrap();
        blob.blob.ciphertext[0] ^= 0x01;
        assert!(decrypt_item(&blob, &vault).is_err());
    }

    #[test]
    fn tampering_payload_nonce_fails() {
        let vault = fresh_vault();
        let mut blob = encrypt_item(b"hello", &vault).unwrap();
        blob.blob.nonce[0] ^= 0x01;
        assert!(decrypt_item(&blob, &vault).is_err());
    }

    #[test]
    fn tampering_wrapped_item_key_fails() {
        let vault = fresh_vault();
        let mut blob = encrypt_item(b"hello", &vault).unwrap();
        blob.wrapped_item_key.ciphertext[0] ^= 0x01;
        assert!(decrypt_item(&blob, &vault).is_err());
    }

    #[test]
    fn item_does_not_decrypt_under_different_vault() {
        let v1 = fresh_vault();
        let v2 = fresh_vault();
        let blob = encrypt_item(b"hello", &v1).unwrap();
        assert!(decrypt_item(&blob, &v2).is_err());
    }

    #[test]
    fn json_blob_does_not_contain_plaintext() {
        let vault = fresh_vault();
        let plaintext = b"super-secret-password-DO-NOT-LEAK";
        let blob = encrypt_item(plaintext, &vault).unwrap();
        let json = serde_json::to_string(&blob).unwrap();
        // 明文 ASCII 不应出现在 JSON
        assert!(!json.contains("super-secret-password"));
        assert!(!json.contains("DO-NOT-LEAK"));
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let vault = fresh_vault();
        let blob = encrypt_item(b"", &vault).unwrap();
        let decrypted = decrypt_item(&blob, &vault).unwrap();
        assert!(decrypted.is_empty());
    }

    /// 持久化 blob 的 version 字段被改成非当前版本 → 拒绝。
    #[test]
    fn decrypt_rejects_unsupported_version() {
        let vault = fresh_vault();
        let mut blob = encrypt_item(b"hi", &vault).unwrap();
        blob.version = 999;
        let r = decrypt_item(&blob, &vault);
        assert!(matches!(r, Err(crate::CryptoError::UnsupportedVersion(999))));
    }

    /// 加密后 JSON round-trip:磁盘上落下来再读回应当还能解密。
    #[test]
    fn blob_json_round_trip_still_decrypts() {
        let vault = fresh_vault();
        let blob = encrypt_item(b"persistent", &vault).unwrap();
        let s = serde_json::to_string(&blob).unwrap();
        let back: EncryptedItemBlob = serde_json::from_str(&s).unwrap();
        let pt = decrypt_item(&back, &vault).unwrap();
        assert_eq!(pt.as_slice(), b"persistent");
    }

    /// 大 payload(1 MiB)亦能 round-trip。
    #[test]
    fn large_payload_round_trips() {
        let vault = fresh_vault();
        let big = vec![0x42u8; 1024 * 1024];
        let blob = encrypt_item(&big, &vault).unwrap();
        let pt = decrypt_item(&blob, &vault).unwrap();
        assert_eq!(pt.as_slice(), big.as_slice());
    }
}
