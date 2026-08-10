//! AEAD 封装。
//!
//! - **AES-256-GCM-SIV**(RFC 8452,12B nonce):用于包装下层密钥。密钥短(32B),
//!   需要 AAD 绑定上下文。选 GCM-**SIV** 而非裸 GCM 的原因:包裹密钥(KEK/VMK/IKEK
//!   等)长命且无轮换出口,GCM-SIV 是 nonce-misuse-resistant —— 即便 RNG 偶发重复
//!   nonce,也只泄露"两条明文是否相等",不像 GCM 那样一次 nonce 复用即可恢复认证
//!   密钥、XOR 出明文。这是长命包裹密钥的最佳实践(Tink 等同款选型)。
//! - **XChaCha20-Poly1305**(24B nonce):用于加密 item payload。payload 可能任意长,
//!   24B nonce 取自随机数后碰撞概率可忽略,适合大量并发加密。
//!
//! **nonce 永不复用**:每次加密都从 OS RNG 取新 nonce。本模块的 `*_seal` 函数自动生成
//! nonce 并嵌入返回结构,调用方**禁止**手动指定 nonce(API 层面就没暴露)。

use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::keys::SymmetricKey;
use crate::random;

/// AES-256-GCM-SIV nonce 长度(RFC 8452,12B)。
pub const AES_GCM_NONCE_LEN: usize = 12;
/// XChaCha20-Poly1305 nonce 长度。
pub const XCHACHA_NONCE_LEN: usize = 24;

/// 一段被 AES-256-GCM-SIV 包装的对称密钥。
///
/// 序列化为 `{nonce: bytes, ciphertext: bytes}`,密文里包含 16B 认证 tag(POLYVAL)。
/// `ciphertext` 长度恒为 32(明文密钥) + 16(tag) = 48 字节。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WrappedKey {
    /// AES-GCM-SIV 12 字节 nonce。
    #[serde(with = "nonce_12_bytes")]
    pub nonce: [u8; AES_GCM_NONCE_LEN],
    /// 32 + 16 字节密文。
    pub ciphertext: Vec<u8>,
}

/// XChaCha20-Poly1305 加密的不透明数据。用于 item payload。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedBlob {
    /// 24 字节 nonce。
    #[serde(with = "nonce_24_bytes")]
    pub nonce: [u8; XCHACHA_NONCE_LEN],
    /// 密文 + 16B tag。
    pub ciphertext: Vec<u8>,
}

/// 用 KEK 把 32 字节密钥包装起来。
pub(crate) fn wrap_key(
    kek: &SymmetricKey,
    plaintext_key: &SymmetricKey,
    aad: &[u8],
) -> Result<WrappedKey> {
    let cipher =
        Aes256GcmSiv::new_from_slice(kek.expose_secret()).map_err(|_| CryptoError::EncryptFailed)?;
    let nonce_bytes = random::bytes::<AES_GCM_NONCE_LEN>()?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm_siv::aead::Payload {
                msg: plaintext_key.expose_secret(),
                aad,
            },
        )
        .map_err(|_| CryptoError::EncryptFailed)?;
    Ok(WrappedKey {
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// 用 KEK 解开包装,返回明文 32 字节密钥(zeroize on drop)。
pub(crate) fn unwrap_key(
    kek: &SymmetricKey,
    wrapped: &WrappedKey,
    aad: &[u8],
) -> Result<SymmetricKey> {
    let cipher =
        Aes256GcmSiv::new_from_slice(kek.expose_secret()).map_err(|_| CryptoError::DecryptFailed)?;
    let nonce = Nonce::from_slice(&wrapped.nonce);
    let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                aes_gcm_siv::aead::Payload {
                    msg: &wrapped.ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::DecryptFailed)?,
    );
    SymmetricKey::try_from_slice(&plaintext)
}

/// 用对称密钥 + AAD 加密任意 payload(item)。
/// 跨模块版本 — `seal_blob` 的 `pub(crate)` 限制对 shared_vault 不够用,因为
/// shared_vault 模块虽在同 crate 内,但 `SymmetricKey` 是私有的,这里提供一个
/// crate-internal 的 alias 仅给 shared_vault item 加密路径用。
pub(crate) fn seal_blob_external(
    key: &SymmetricKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<SealedBlob> {
    seal_blob(key, plaintext, aad)
}

/// 跨模块版本 — `open_blob` 的同名对端。
pub(crate) fn open_blob_external(
    key: &SymmetricKey,
    blob: &SealedBlob,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    open_blob(key, blob, aad)
}

pub(crate) fn seal_blob(key: &SymmetricKey, plaintext: &[u8], aad: &[u8]) -> Result<SealedBlob> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose_secret())
        .map_err(|_| CryptoError::EncryptFailed)?;
    let nonce_bytes = random::bytes::<XCHACHA_NONCE_LEN>()?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::EncryptFailed)?;
    Ok(SealedBlob {
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// 解密 [`SealedBlob`],返回 zeroize 包装的明文。
pub(crate) fn open_blob(
    key: &SymmetricKey,
    blob: &SealedBlob,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose_secret())
        .map_err(|_| CryptoError::DecryptFailed)?;
    let nonce = XNonce::from_slice(&blob.nonce);
    let plaintext = cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: &blob.ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::DecryptFailed)?;
    Ok(Zeroizing::new(plaintext))
}

macro_rules! nonce_serde_module {
    ($mod_name:ident, $len:expr) => {
        mod $mod_name {
            use serde::{Deserialize, Deserializer, Serializer};

            pub fn serialize<S: Serializer>(
                value: &[u8; $len],
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(value)
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(
                deserializer: D,
            ) -> Result<[u8; $len], D::Error> {
                let v = <Vec<u8>>::deserialize(deserializer)?;
                if v.len() != $len {
                    return Err(serde::de::Error::custom(format!(
                        "expected {} bytes, got {}",
                        $len,
                        v.len()
                    )));
                }
                let mut out = [0u8; $len];
                out.copy_from_slice(&v);
                Ok(out)
            }
        }
    };
}

nonce_serde_module!(nonce_12_bytes, 12);
nonce_serde_module!(nonce_24_bytes, 24);

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SymmetricKey {
        SymmetricKey::random().unwrap()
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        let kek = key();
        let target = key();
        let aad = b"rootkey-test/v1/account/vault";

        let wrapped = wrap_key(&kek, &target, aad).unwrap();
        assert_eq!(wrapped.ciphertext.len(), 32 + 16);

        let unwrapped = unwrap_key(&kek, &wrapped, aad).unwrap();
        assert_eq!(unwrapped.expose_secret(), target.expose_secret());
    }

    #[test]
    fn unwrap_fails_with_wrong_kek() {
        let kek = key();
        let other = key();
        let target = key();
        let wrapped = wrap_key(&kek, &target, b"aad").unwrap();
        assert!(unwrap_key(&other, &wrapped, b"aad").is_err());
    }

    #[test]
    fn unwrap_fails_with_wrong_aad() {
        let kek = key();
        let target = key();
        let wrapped = wrap_key(&kek, &target, b"aad-1").unwrap();
        assert!(unwrap_key(&kek, &wrapped, b"aad-2").is_err());
    }

    #[test]
    fn seal_open_round_trip() {
        let k = key();
        let plaintext = b"my secret note text";
        let blob = seal_blob(&k, plaintext, b"vault-aad").unwrap();
        let opened = open_blob(&k, &blob, b"vault-aad").unwrap();
        assert_eq!(opened.as_slice(), plaintext);
    }

    #[test]
    fn same_plaintext_two_encrypts_have_different_ciphertexts() {
        let k = key();
        let plaintext = b"same";
        let a = seal_blob(&k, plaintext, b"aad").unwrap();
        let b = seal_blob(&k, plaintext, b"aad").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn open_fails_after_ciphertext_tamper() {
        let k = key();
        let mut blob = seal_blob(&k, b"hello", b"aad").unwrap();
        blob.ciphertext[0] ^= 0x01;
        assert!(open_blob(&k, &blob, b"aad").is_err());
    }

    #[test]
    fn open_fails_after_nonce_tamper() {
        let k = key();
        let mut blob = seal_blob(&k, b"hello", b"aad").unwrap();
        blob.nonce[0] ^= 0x01;
        assert!(open_blob(&k, &blob, b"aad").is_err());
    }

    /// WrappedKey / SealedBlob 序列化 → 反序列化 round-trip。
    #[test]
    fn wrapped_key_json_round_trip() {
        let kek = key();
        let target = key();
        let wrapped = wrap_key(&kek, &target, b"aad").unwrap();
        let s = serde_json::to_string(&wrapped).unwrap();
        let parsed: WrappedKey = serde_json::from_str(&s).unwrap();
        assert_eq!(wrapped, parsed);
    }

    #[test]
    fn sealed_blob_json_round_trip() {
        let k = key();
        let blob = seal_blob(&k, b"x", b"aad").unwrap();
        let s = serde_json::to_string(&blob).unwrap();
        let parsed: SealedBlob = serde_json::from_str(&s).unwrap();
        assert_eq!(blob, parsed);
    }

    /// 反序列化 nonce 字节数错误 → 解析失败。
    #[test]
    fn deserialize_wrong_nonce_length_fails() {
        // 用 13 字节 nonce 伪造 WrappedKey 应该失败
        let bad = serde_json::json!({
            "nonce": vec![0u8; 13],
            "ciphertext": vec![0u8; 48],
        });
        let r: serde_json::Result<WrappedKey> = serde_json::from_value(bad);
        assert!(r.is_err());

        // 24 字节 SealedBlob 同理:23 字节就拒绝。
        let bad2 = serde_json::json!({
            "nonce": vec![0u8; 23],
            "ciphertext": vec![0u8; 16],
        });
        let r2: serde_json::Result<SealedBlob> = serde_json::from_value(bad2);
        assert!(r2.is_err());
    }
}
