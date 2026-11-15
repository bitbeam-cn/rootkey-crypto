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
use crate::keys::MasterUnlockKey;

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
    BackupSession::create(password)?.seal_main(plaintext)
}

/// 用密码解开 bundle,返回 zeroize 包装的明文。
pub fn open_with_password(password: &str, bundle: &EncryptedBundle) -> Result<Zeroizing<Vec<u8>>> {
    BackupSession::for_bundle(password, bundle)?.open_main(bundle)
}

/// 同一个导出密码下加密 / 解开多段数据的会话:Argon2id 只跑一次。
///
/// 备份除了主体(全部条目,[`EncryptedBundle`])还要带附件。附件逐个单独加密、
/// 逐个写盘,这样整份备份不必同时放在内存里;每跑一次 Argon2id 要上百毫秒和几十 MB 内存,
/// 所以密钥只派生一次,各段共用。
///
/// 各段用同一把密钥、各自随机的 24 字节 nonce;AAD 把每段绑在「这份备份(KDF 参数)+
/// 这一段的标签」上:主体和附件互相替换不了,两个附件对调、挪到另一份备份里也都解不开。
pub struct BackupSession {
    muk: MasterUnlockKey,
    kdf: KdfParams,
}

impl BackupSession {
    /// 新建一份备份:随机盐,派生密钥。
    pub fn create(password: &str) -> Result<Self> {
        let kdf = KdfParams::generate_default()?;
        let muk = derive_muk(password, &kdf)?;
        Ok(Self { muk, kdf })
    }

    /// 打开已有的备份:按包里的 KDF 参数派生密钥。
    /// 密码对不对在这里看不出来,要到 [`Self::open_main`] 解主体时才知道。
    pub fn for_bundle(password: &str, bundle: &EncryptedBundle) -> Result<Self> {
        if bundle.magic != EXPORT_MAGIC {
            return Err(CryptoError::InvalidArgument("bundle magic mismatch"));
        }
        let muk = derive_muk(password, &bundle.kdf)?;
        Ok(Self {
            muk,
            kdf: bundle.kdf.clone(),
        })
    }

    /// 加密主体。
    pub fn seal_main(&self, plaintext: &[u8]) -> Result<EncryptedBundle> {
        let blob = seal_blob(&self.muk.0, plaintext, &aad_bytes(&self.kdf))?;
        Ok(EncryptedBundle {
            magic: EXPORT_MAGIC.to_string(),
            kdf: self.kdf.clone(),
            blob,
        })
    }

    /// 解开主体。密码不对、内容被改都在这里失败。
    pub fn open_main(&self, bundle: &EncryptedBundle) -> Result<Zeroizing<Vec<u8>>> {
        if bundle.magic != EXPORT_MAGIC {
            return Err(CryptoError::InvalidArgument("bundle magic mismatch"));
        }
        open_blob(&self.muk.0, &bundle.blob, &aad_bytes(&bundle.kdf))
    }

    /// 加密主体之外的一段(一个附件)。`label` 是这一段的身份(附件 id),进 AAD。
    pub fn seal_part(&self, label: &[u8], plaintext: &[u8]) -> Result<SealedBlob> {
        seal_blob(&self.muk.0, plaintext, &part_aad(&self.kdf, label))
    }

    /// 解开一段。`label` 必须和加密时相同。
    pub fn open_part(&self, label: &[u8], blob: &SealedBlob) -> Result<Zeroizing<Vec<u8>>> {
        open_blob(&self.muk.0, blob, &part_aad(&self.kdf, label))
    }
}

/// 把 KDF 参数序列化为 AAD,绑定密文与 KDF 上下文(防降级 / 篡改攻击)。
fn aad_bytes(kdf: &KdfParams) -> Vec<u8> {
    let mut out = Vec::with_capacity(EXPORT_MAGIC.len() + 64);
    out.extend_from_slice(EXPORT_MAGIC.as_bytes());
    out.extend_from_slice(&kdf.aad_bytes());
    out
}

/// 附件段的 AAD:主体的 AAD + 固定分隔 + 标签。主体的 AAD 是它的真前缀,两者不会相等。
fn part_aad(kdf: &KdfParams, label: &[u8]) -> Vec<u8> {
    let mut out = aad_bytes(kdf);
    out.extend_from_slice(b"/part/");
    out.extend_from_slice(label);
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

    #[test]
    fn session_round_trips_main_and_parts() {
        let s = BackupSession::create("pw").unwrap();
        let bundle = s.seal_main(b"items").unwrap();
        let a = s.seal_part(b"att-a", b"file a").unwrap();
        let b = s.seal_part(b"att-b", b"file b").unwrap();

        let o = BackupSession::for_bundle("pw", &bundle).unwrap();
        assert_eq!(&o.open_main(&bundle).unwrap()[..], b"items");
        assert_eq!(&o.open_part(b"att-a", &a).unwrap()[..], b"file a");
        assert_eq!(&o.open_part(b"att-b", &b).unwrap()[..], b"file b");
        // 老接口读新会话写的主体:格式没变
        assert_eq!(&open_with_password("pw", &bundle).unwrap()[..], b"items");
    }

    /// 两个附件对调、附件冒充主体、主体冒充附件,都解不开。
    #[test]
    fn parts_are_bound_to_their_label_and_role() {
        let s = BackupSession::create("pw").unwrap();
        let bundle = s.seal_main(b"items").unwrap();
        let a = s.seal_part(b"att-a", b"file a").unwrap();
        assert!(s.open_part(b"att-b", &a).is_err());
        assert!(s.open_part(b"", &bundle.blob).is_err());
        let mut forged = bundle.clone();
        forged.blob = a;
        assert!(s.open_main(&forged).is_err());
    }

    /// 附件挪到另一份备份里(同密码、不同盐)解不开。
    #[test]
    fn parts_do_not_open_under_another_backup() {
        let s1 = BackupSession::create("pw").unwrap();
        let s2 = BackupSession::create("pw").unwrap();
        let a = s1.seal_part(b"att-a", b"file a").unwrap();
        assert!(s2.open_part(b"att-a", &a).is_err());
    }

    #[test]
    fn session_wrong_password_fails_at_open_main() {
        let s = BackupSession::create("right").unwrap();
        let bundle = s.seal_main(b"items").unwrap();
        let o = BackupSession::for_bundle("wrong", &bundle).unwrap();
        assert!(o.open_main(&bundle).is_err());
    }
}
