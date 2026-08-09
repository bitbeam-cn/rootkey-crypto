//! 密码加密的备份 / 恢复包。
//!
//! 用户提供一个**导出密码**(通常等于 vault 主密码),生成自包含的加密包:
//! Argon2id(password, random_salt) → key
//! XChaCha20-Poly1305(plaintext, random_nonce, key) → ciphertext
//!
//! 包是 JSON,可在任何 RootKey 实例上恢复 — 不依赖原 vault 的密钥文件。

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::aead::{open_blob, seal_blob, SealedBlob};
use crate::error::{CryptoError, Result};
use crate::kdf::{derive_muk, KdfParams};

/// 导出包格式版本。变更值意味着不向后兼容,旧客户端拒绝解。
pub const EXPORT_MAGIC: &str = "ROOTKEY_VAULT_BACKUP_V1";

/// 加密备份包。序列化后写盘 / 跨设备传输。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBundle {
    /// 防误用魔术串。
    pub magic: String,
    /// Argon2id 参数(含 32B 随机 salt)。
    pub kdf: KdfParams,
    /// 密文 + 24B nonce + 16B Poly1305 tag。
    pub blob: SealedBlob,
}

/// 用密码加密任意 plaintext 字节。返回的 bundle 可序列化为 JSON。
pub fn seal_with_password(password: &str, plaintext: &[u8]) -> Result<EncryptedBundle> {
    let kdf = KdfParams::generate_default()?;
    let muk = derive_muk(password, &kdf)?;
    let aad = aad_bytes(&kdf);
    let blob = seal_blob(&muk.0, plaintext, &aad)?;
    Ok(EncryptedBundle {
        magic: EXPORT_MAGIC.to_string(),
        kdf,
        blob,
    })
}

/// 用密码解开 bundle,返回 zeroize 包装的明文。
pub fn open_with_password(password: &str, bundle: &EncryptedBundle) -> Result<Zeroizing<Vec<u8>>> {
    if bundle.magic != EXPORT_MAGIC {
        return Err(CryptoError::InvalidArgument("bundle magic mismatch"));
    }
    let muk = derive_muk(password, &bundle.kdf)?;
    let aad = aad_bytes(&bundle.kdf);
    open_blob(&muk.0, &bundle.blob, &aad)
}

/// 把 KDF 参数序列化为 AAD,绑定密文与 KDF 上下文(防降级 / 篡改攻击)。
fn aad_bytes(kdf: &KdfParams) -> Vec<u8> {
    let mut out = Vec::with_capacity(EXPORT_MAGIC.len() + 64);
    out.extend_from_slice(EXPORT_MAGIC.as_bytes());
    out.extend_from_slice(&kdf.aad_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let plaintext = b"hello vault backup";
        let bundle = seal_with_password("master-pass-x9!Q", plaintext).unwrap();
        let opened = open_with_password("master-pass-x9!Q", &bundle).unwrap();
        assert_eq!(&opened[..], plaintext);
    }

    #[test]
    fn wrong_password_rejected() {
        let bundle = seal_with_password("right", b"data").unwrap();
        let err = open_with_password("wrong", &bundle);
        assert!(err.is_err());
    }

    #[test]
    fn tampered_magic_rejected() {
        let mut bundle = seal_with_password("p", b"data").unwrap();
        bundle.magic = "ROOTKEY_VAULT_BACKUP_V2".into();
        assert!(open_with_password("p", &bundle).is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let mut bundle = seal_with_password("p", b"data").unwrap();
        bundle.blob.ciphertext[0] ^= 0xff;
        assert!(open_with_password("p", &bundle).is_err());
    }

    /// magic 字段被改成空串也算"不匹配"。
    #[test]
    fn tampered_empty_magic_rejected() {
        let mut bundle = seal_with_password("p", b"data").unwrap();
        bundle.magic = String::new();
        let r = open_with_password("p", &bundle);
        assert!(matches!(r, Err(CryptoError::InvalidArgument(_))));
    }

    /// kdf 参数被改 → AAD 不匹配 → 解密失败。
    /// 防止攻击者把 kdf 参数降级(虽然 validate 已经把太低的拦掉,
    /// 这里测的是 "降到合法但与原文不同" 也得失败)。
    #[test]
    fn tampered_kdf_salt_rejected() {
        let mut bundle = seal_with_password("p", b"data").unwrap();
        bundle.kdf.salt[0] ^= 0xff;
        assert!(open_with_password("p", &bundle).is_err());
    }

    /// 序列化 / 反序列化往返。
    #[test]
    fn bundle_json_round_trip() {
        let bundle = seal_with_password("p", b"data").unwrap();
        let s = serde_json::to_string(&bundle).unwrap();
        let back: EncryptedBundle = serde_json::from_str(&s).unwrap();
        let pt = open_with_password("p", &back).unwrap();
        assert_eq!(&*pt, b"data");
    }
}
