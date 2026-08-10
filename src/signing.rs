//! Ed25519 数字签名(Phase 2:vault 文件级签名)。
//!
//! 用途:同步层(WebDAV / Dropbox / iCloud)有可能在中间篡改密文。AEAD 保证
//! "用同一把 ItemKey 解密能拿到原文" 的完整性,**但**同步层可以删/换/回滚整个
//! `manifest.enc` / `items/{id}.item` 文件 —— AEAD 不阻止这种"用旧密文换新密文"
//! 的攻击,因为旧密文本身合法。
//!
//! 引入 vault-level 的 Ed25519 签名:
//! - 每个 vault 一对 keypair,private 用 VMK AEAD-wrap 存盘
//! - 落盘的 manifest / item / history 写一份 `.sig` 文件
//! - unlock 时校验签名,失败 → 拒绝加载(同步层被改了)
//!
//! 这是 belt-and-suspenders:AEAD 保密 + 内部完整性,签名补 vault 级 binding。
//!
//! ## Limitation(已 documented)
//! - 不防"整个 vault 目录被复制粘贴到老快照回滚":需要 monotonic version + 服务端
//!   状态来防 replay。本模块只防"被换文件"。
//! - 没有 multi-device signing chain:这里的 keypair 是 vault-scoped 共享,不是
//!   device-scoped — 多设备各自签名(device-bound)是更高阶的设计,Phase 3 再说。

use core::fmt;

use ed25519_dalek::{
    Signature as DalekSignature, SignatureError, Signer, SigningKey as DalekSigningKey,
    VerifyingKey as DalekVerifyingKey,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::error::{CryptoError, Result};

/// Ed25519 私钥(32 字节种子)。
///
/// `Drop` 时 zeroize(`ed25519-dalek` 启用了 `zeroize` feature,内部 `SecretKey`
/// 已经 `ZeroizeOnDrop`)。**永远不要**把字节 clone 到长期存储 / 日志 / 错误信息。
#[derive(ZeroizeOnDrop)]
pub struct SigningKey(DalekSigningKey);

impl SigningKey {
    /// 从 OS RNG(`crypto_core::random`)生成。**生产代码默认走这条**。
    pub fn generate_os() -> Result<Self> {
        let bytes = crate::random::bytes::<32>()?;
        Ok(Self(DalekSigningKey::from_bytes(&bytes)))
    }

    /// 从 32 字节 seed 构造。仅在已经从安全存储拿到 seed(eg. VMK-decrypted)时调用。
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(DalekSigningKey::from_bytes(bytes))
    }

    /// 暴露 32 字节 seed —— **仅** crate 内部 / vault 持久化层使用。
    ///
    /// 返回 `Zeroizing`:调用方持有期间是明文,drop 时自动擦除,避免拷贝残留内存。
    #[doc(hidden)]
    pub fn expose_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// 对消息字节签名。Ed25519 的 ctx 我们留空(IETF 标准 PureEd25519)。
    pub fn sign(&self, msg: &[u8]) -> Signature {
        let sig = self.0.sign(msg);
        Signature(sig.to_bytes())
    }

    /// 派生对应的 [`VerifyingKey`](public key)。
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(REDACTED)")
    }
}

/// Ed25519 公钥(32 字节)。
///
/// 公开数据,可序列化 / 写盘 / 同步。落 `vault_pub.bin`(64 字节十六进制 或 32 字节 raw)。
#[derive(Clone, PartialEq, Eq)]
pub struct VerifyingKey(DalekVerifyingKey);

impl VerifyingKey {
    /// 从 32 字节构造。任何字段不合法 → [`CryptoError::InvalidArgument`]。
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        DalekVerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidArgument("invalid ed25519 verifying key"))
    }

    /// 32 字节 raw public key 表示。
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// 校验 `msg` 上的签名。错误信息**不**区分"密文损坏 / 签名不匹配 / 公钥不对",
    /// 统一返回 [`CryptoError::SignatureInvalid`]。
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        let dalek_sig = DalekSignature::from_bytes(&sig.0);
        // 用 verify_strict 拒掉小子群伪签名 / 非规范 R 值(更严格,推荐)
        self.0
            .verify_strict(msg, &dalek_sig)
            .map_err(|_: SignatureError| CryptoError::SignatureInvalid)
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("bytes", &"[..32]")
            .finish()
    }
}

impl Serialize for VerifyingKey {
    fn serialize<S: Serializer>(&self, ser: S) -> core::result::Result<S::Ok, S::Error> {
        ser.serialize_bytes(&self.0.to_bytes())
    }
}

impl<'de> Deserialize<'de> for VerifyingKey {
    fn deserialize<D: Deserializer<'de>>(de: D) -> core::result::Result<Self, D::Error> {
        let v = <Vec<u8>>::deserialize(de)?;
        if v.len() != 32 {
            return Err(serde::de::Error::custom("verifying key must be 32 bytes"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&v);
        DalekVerifyingKey::from_bytes(&bytes)
            .map(Self)
            .map_err(|_| serde::de::Error::custom("invalid ed25519 verifying key"))
    }
}

/// Ed25519 签名(64 字节)。
#[derive(Clone, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl Signature {
    /// 从 64 字节构造。
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// 64 字节 raw signature 表示。
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature")
            .field("bytes", &"[..64]")
            .finish()
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, ser: S) -> core::result::Result<S::Ok, S::Error> {
        ser.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(de: D) -> core::result::Result<Self, D::Error> {
        let v = <Vec<u8>>::deserialize(de)?;
        if v.len() != 64 {
            return Err(serde::de::Error::custom("signature must be 64 bytes"));
        }
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&v);
        Ok(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_round_trip() {
        let sk = SigningKey::generate_os().unwrap();
        let vk = sk.verifying_key();
        let msg = b"hello vault";
        let sig = sk.sign(msg);
        vk.verify(msg, &sig).unwrap();
    }

    #[test]
    fn wrong_message_verify_fails() {
        let sk = SigningKey::generate_os().unwrap();
        let vk = sk.verifying_key();
        let sig = sk.sign(b"original");
        assert!(matches!(
            vk.verify(b"tampered", &sig),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn wrong_verifying_key_fails() {
        let sk_a = SigningKey::generate_os().unwrap();
        let sk_b = SigningKey::generate_os().unwrap();
        let vk_b = sk_b.verifying_key();
        let msg = b"msg";
        let sig = sk_a.sign(msg);
        assert!(matches!(
            vk_b.verify(msg, &sig),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn signature_tamper_one_byte_rejected() {
        let sk = SigningKey::generate_os().unwrap();
        let vk = sk.verifying_key();
        let msg = b"important";
        let mut sig = sk.sign(msg);
        sig.0[0] ^= 0x01;
        assert!(matches!(
            vk.verify(msg, &sig),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn from_bytes_round_trip_keeps_keypair() {
        let sk1 = SigningKey::generate_os().unwrap();
        let seed = sk1.expose_seed();
        let sk2 = SigningKey::from_bytes(&seed);
        let msg = b"determinism check";
        let sig1 = sk1.sign(msg);
        let sig2 = sk2.sign(msg);
        // Ed25519 是确定性签名,同 key + 同 msg 必产同 sig
        assert_eq!(sig1.0, sig2.0);
        assert_eq!(
            sk1.verifying_key().to_bytes(),
            sk2.verifying_key().to_bytes()
        );
    }

    #[test]
    fn verifying_key_serde_round_trip() {
        let sk = SigningKey::generate_os().unwrap();
        let vk = sk.verifying_key();
        let s = serde_json::to_string(&vk).unwrap();
        let back: VerifyingKey = serde_json::from_str(&s).unwrap();
        assert_eq!(back.to_bytes(), vk.to_bytes());
    }

    #[test]
    fn signature_serde_round_trip() {
        let sk = SigningKey::generate_os().unwrap();
        let sig = sk.sign(b"x");
        let s = serde_json::to_string(&sig).unwrap();
        let back: Signature = serde_json::from_str(&s).unwrap();
        assert_eq!(back.0, sig.0);
    }

    #[test]
    fn verifying_key_serde_rejects_wrong_length() {
        let bad = serde_json::json!(vec![0u8; 31]);
        let r: serde_json::Result<VerifyingKey> = serde_json::from_value(bad);
        assert!(r.is_err());
    }

    #[test]
    fn signature_serde_rejects_wrong_length() {
        let bad = serde_json::json!(vec![0u8; 63]);
        let r: serde_json::Result<Signature> = serde_json::from_value(bad);
        assert!(r.is_err());
    }

    #[test]
    fn debug_does_not_leak_seed() {
        let sk = SigningKey::generate_os().unwrap();
        let s = format!("{sk:?}");
        assert!(s.contains("REDACTED"));
    }

    /// RFC 8032 §7.1 Test 1:empty message, known seed → known signature.
    /// Seed:  9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
    /// Pub:   d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
    /// Msg:   (empty)
    /// Sig:   e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
    #[test]
    fn rfc8032_test_1_empty_message() {
        let seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let pub_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

        let seed: [u8; 32] = hex::decode(seed_hex).unwrap().try_into().unwrap();
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        assert_eq!(hex::encode(vk.to_bytes()), pub_hex);

        let sig = sk.sign(b"");
        assert_eq!(hex::encode(sig.0), sig_hex);
        vk.verify(b"", &sig).unwrap();
    }

    /// RFC 8032 §7.1 Test 2:single-byte message 0x72.
    /// Seed:  4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
    /// Pub:   3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
    /// Msg:   72
    /// Sig:   92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00
    #[test]
    fn rfc8032_test_2_single_byte_message() {
        let seed_hex = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
        let pub_hex = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
        let sig_hex = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

        let seed: [u8; 32] = hex::decode(seed_hex).unwrap().try_into().unwrap();
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        assert_eq!(hex::encode(vk.to_bytes()), pub_hex);

        let msg = [0x72u8];
        let sig = sk.sign(&msg);
        assert_eq!(hex::encode(sig.0), sig_hex);
        vk.verify(&msg, &sig).unwrap();
    }
}
