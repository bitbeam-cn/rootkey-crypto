//! Item 单条共享 envelope(ADR-005,Phase 1)。
//!
//! 与 vault 加密链路解耦:用一次性随机 32B key 直接 XChaCha20-Poly1305 加密
//! envelope 明文。Key **不** 嵌入 envelope,由用户单独分发(另一条传输通道)。
//!
//! ## 安全约束
//!
//! - **key 永不嵌入 envelope**:envelope 拿到 ≠ 解密
//! - **每次 share 重新随机 32B key + 24B nonce**,不复用
//! - **expires_at 进 AAD**:篡改过期时间 → 解密失败
//! - **接收端必须用本模块校验 expires_at**(`open_share` 已经做了)
//! - **key 字符串编码失败的具体原因不向调用方泄露**(校验和 / 长度 / 字母表 / 前缀
//!   都映射到统一 [`CryptoError::InvalidArgument("invalid share key")`])
//!
//! 详见 `docs/adr/0005-item-share-link.md`。

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::aead::XCHACHA_NONCE_LEN;
use crate::error::{CryptoError, Result};
use crate::keys::SymmetricKey;
use crate::random;

/// share envelope 二进制 header 标识。
pub const SHARE_HEADER: &[u8] = b"rootkey-share-v1";

/// AAD 前缀;实际 AAD = `SHARE_AAD_PREFIX || expires_at_be_u64`。
const SHARE_AAD_PREFIX: &[u8] = b"rootkey-share/v1/";

/// key 字符串前缀 —— `RKS1-...`(RootKey Share)。与账号恢复密钥的 `RK-` 前缀
/// 区分:两者都是用户手里的一串字符,前缀不同才能一眼看出该往哪个框里贴。
const KEY_PREFIX: &str = "RKS1";

/// key 校验和域分隔标签(BLAKE3 personalization 风格)。
const KEY_CHECKSUM_DOMAIN: &[u8] = b"rootkey-share-key-checksum-v1";

/// key 校验和字节数。**不是**安全防线,只防用户复制粘贴时漏字符 / 多字符。
const KEY_CHECKSUM_LEN: usize = 5;

/// Crockford Base32 字母表(剔除 I L O U,与 Recovery Kit 一致)。
const CROCKFORD_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Crockford Base32 编码 — 输入任意字节,输出无 padding 大写字符串。
/// 32B + 5B = 37B 输入 → ceil(37×8/5) = 60 字符。
fn crockford_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() * 8 + 4) / 5);
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for &b in input {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buf >> bits) & 0x1F) as usize;
            out.push(CROCKFORD_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buf << (5 - bits)) & 0x1F) as usize;
        out.push(CROCKFORD_ALPHABET[idx] as char);
    }
    out
}

/// Crockford Base32 解码 — 输入字母统一 upper、已规整 I/L→1、O→0;非字母表字符返回 None。
fn crockford_decode(input: &str) -> Option<Vec<u8>> {
    // Build inverse lookup once.
    let mut table = [0xFFu8; 256];
    for (i, &c) in CROCKFORD_ALPHABET.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for c in input.bytes() {
        let v = table[c as usize];
        if v == 0xFF {
            return None;
        }
        buf = (buf << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    // 剩余 bits 若不全 0,说明 padding 有 trailing junk → 拒绝
    if bits > 0 && (buf & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

/// 32 字节 share key + 5 字节校验和。
///
/// 用户层文本格式:`RKS1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`,7 段 ×
/// 5 字符 = 35 字符的 Crockford Base32 编码(对应 32B+5B = 37B,实际 base32
/// 输出有 padding,我们用无 padding 输出 60 字符,再分 5 段)。
#[derive(Clone)]
pub struct ShareKey {
    bytes: Zeroizing<[u8; SymmetricKey::LEN]>,
}

impl ShareKey {
    /// 32 字节明文 key 长度。
    pub const LEN: usize = SymmetricKey::LEN;

    /// 全新随机 key。
    pub fn random() -> Result<Self> {
        let raw = random::bytes::<{ SymmetricKey::LEN }>()?;
        Ok(Self {
            bytes: Zeroizing::new(raw),
        })
    }

    /// 从 32 字节裸值构造。用于解析后的还原,生产代码不建议直接用。
    pub fn from_bytes(bytes: [u8; SymmetricKey::LEN]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// 暴露字节给加密原语。**禁止**写入日志 / 错误信息 / debug。
    pub fn expose_secret(&self) -> &[u8; SymmetricKey::LEN] {
        &self.bytes
    }

    /// 编码成用户可分发的字符串:`RKS1-XXXXX-...-XXXXX`。
    pub fn encode(&self) -> String {
        let mut full = [0u8; SymmetricKey::LEN + KEY_CHECKSUM_LEN];
        full[..SymmetricKey::LEN].copy_from_slice(&self.bytes[..]);
        full[SymmetricKey::LEN..].copy_from_slice(&checksum(&self.bytes[..]));
        let encoded = crockford_encode(&full);
        // 5 字符一段,以 `-` 分隔,加 `RKS1-` 前缀。
        let mut grouped = String::with_capacity(KEY_PREFIX.len() + encoded.len() + encoded.len() / 5);
        grouped.push_str(KEY_PREFIX);
        for (i, ch) in encoded.chars().enumerate() {
            if i % 5 == 0 {
                grouped.push('-');
            }
            grouped.push(ch);
        }
        full.zeroize();
        grouped
    }

    /// 从用户输入字符串解析 + 校验和检查。
    ///
    /// 容忍大小写 / 空格 / 多余 `-`。任何失败原因都返回同一错误,**不**透露原因。
    pub fn parse(input: &str) -> Result<Self> {
        let stripped: String = input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        let upper = stripped.to_ascii_uppercase();

        // 必须以前缀开头。
        let body = upper
            .strip_prefix(KEY_PREFIX)
            .ok_or(CryptoError::InvalidArgument("invalid share key"))?;

        // Crockford 错位字符纠正:I → 1, L → 1, O → 0(U 已剔除,不出现)。
        let normalized: String = body
            .chars()
            .map(|c| match c {
                'I' | 'L' => '1',
                'O' => '0',
                other => other,
            })
            .collect();

        // 解码;长度 / 字母表 / padding 任意错误 → 统一报错
        let decoded = crockford_decode(&normalized)
            .ok_or(CryptoError::InvalidArgument("invalid share key"))?;

        if decoded.len() != SymmetricKey::LEN + KEY_CHECKSUM_LEN {
            return Err(CryptoError::InvalidArgument("invalid share key"));
        }
        let (key_bytes, expected) = decoded.split_at(SymmetricKey::LEN);
        let actual = checksum(key_bytes);

        // 常数时间比较,失败原因不分类
        if !bool::from(expected.ct_eq(&actual)) {
            return Err(CryptoError::InvalidArgument("invalid share key"));
        }

        let mut raw = [0u8; SymmetricKey::LEN];
        raw.copy_from_slice(key_bytes);
        Ok(Self::from_bytes(raw))
    }
}

impl std::fmt::Debug for ShareKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareKey").field("bytes", &"<redacted>").finish()
    }
}

fn checksum(key: &[u8]) -> [u8; KEY_CHECKSUM_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(KEY_CHECKSUM_DOMAIN);
    hasher.update(key);
    let mut out = [0u8; KEY_CHECKSUM_LEN];
    out.copy_from_slice(&hasher.finalize().as_bytes()[..KEY_CHECKSUM_LEN]);
    out
}

/// 加密 envelope 的二进制表示(序列化进文件 / 网络的形态)。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareBlob {
    /// 24 字节 nonce(明文)。
    pub nonce: [u8; XCHACHA_NONCE_LEN],
    /// 密文 + 16B Poly1305 tag。
    pub ciphertext: Vec<u8>,
    /// 过期时间,unix 秒。**在 AAD 内**,篡改会导致解密失败。
    pub expires_at: u64,
}

impl ShareBlob {
    /// 编码成可放进文件 / 复制粘贴的文本(三行):
    ///
    /// ```text
    /// rootkey-share-v1
    /// <base64url(nonce_24B)>
    /// <expires_at_unix>
    /// <base64url(ciphertext)>
    /// ```
    pub fn encode_text(&self) -> String {
        let nonce_b64 = BASE64URL_NOPAD.encode(&self.nonce);
        let ct_b64 = BASE64URL_NOPAD.encode(&self.ciphertext);
        format!(
            "{magic}\n{nonce}\n{exp}\n{ct}\n",
            magic = std::str::from_utf8(SHARE_HEADER).expect("ascii"),
            nonce = nonce_b64,
            exp = self.expires_at,
            ct = ct_b64,
        )
    }

    /// 反向解析。
    pub fn parse_text(text: &str) -> Result<Self> {
        let mut lines = text.lines();
        let magic = lines
            .next()
            .ok_or(CryptoError::InvalidArgument("share blob: missing header"))?;
        if magic.as_bytes() != SHARE_HEADER {
            return Err(CryptoError::UnsupportedVersion(0));
        }
        let nonce_b64 = lines
            .next()
            .ok_or(CryptoError::InvalidArgument("share blob: missing nonce"))?;
        let exp_str = lines
            .next()
            .ok_or(CryptoError::InvalidArgument("share blob: missing exp"))?;
        let ct_b64 = lines
            .next()
            .ok_or(CryptoError::InvalidArgument("share blob: missing ct"))?;

        let nonce_vec = BASE64URL_NOPAD
            .decode(nonce_b64.as_bytes())
            .map_err(|_| CryptoError::InvalidArgument("share blob: nonce decode"))?;
        if nonce_vec.len() != XCHACHA_NONCE_LEN {
            return Err(CryptoError::InvalidArgument("share blob: nonce length"));
        }
        let mut nonce = [0u8; XCHACHA_NONCE_LEN];
        nonce.copy_from_slice(&nonce_vec);

        let expires_at: u64 = exp_str
            .trim()
            .parse()
            .map_err(|_| CryptoError::InvalidArgument("share blob: exp parse"))?;

        let ct = BASE64URL_NOPAD
            .decode(ct_b64.as_bytes())
            .map_err(|_| CryptoError::InvalidArgument("share blob: ct decode"))?;

        Ok(Self {
            nonce,
            ciphertext: ct,
            expires_at,
        })
    }
}

fn aad_for(expires_at: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(SHARE_AAD_PREFIX.len() + 8);
    out.extend_from_slice(SHARE_AAD_PREFIX);
    out.extend_from_slice(&expires_at.to_be_bytes());
    out
}

/// 加密 envelope 明文,返回 (key, blob)。`expires_at` 是 unix 秒,**必须**未来。
pub fn seal_share(plaintext: &[u8], expires_at: u64) -> Result<(ShareKey, ShareBlob)> {
    if plaintext.is_empty() {
        return Err(CryptoError::InvalidArgument("share plaintext empty"));
    }
    let key = ShareKey::random()?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose_secret())
        .map_err(|_| CryptoError::EncryptFailed)?;
    let nonce_bytes = random::bytes::<XCHACHA_NONCE_LEN>()?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let aad = aad_for(expires_at);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::EncryptFailed)?;
    Ok((
        key,
        ShareBlob {
            nonce: nonce_bytes,
            ciphertext,
            expires_at,
        },
    ))
}

/// 解密 envelope。`now_unix` 由调用方提供(测试可注入,生产 `SystemTime::now`)。
///
/// 过期返回 [`CryptoError::DecryptFailed`](与篡改、密钥错统一返回,防侧信道)。
pub fn open_share(blob: &ShareBlob, key: &ShareKey, now_unix: u64) -> Result<Vec<u8>> {
    if now_unix > blob.expires_at {
        return Err(CryptoError::DecryptFailed);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose_secret())
        .map_err(|_| CryptoError::DecryptFailed)?;
    let nonce = XNonce::from_slice(&blob.nonce);
    let aad = aad_for(blob.expires_at);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &blob.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::DecryptFailed)
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const FUTURE: u64 = 2_000_000_000; // 2033-05-18
    const PAST: u64 = 1_000_000_000; // 2001-09-09

    #[test]
    fn round_trip_ok() {
        let (key, blob) = seal_share(b"hello world", FUTURE).unwrap();
        let plain = open_share(&blob, &key, FUTURE - 1).unwrap();
        assert_eq!(plain.as_slice(), b"hello world");
    }

    #[test]
    fn wrong_key_fails() {
        let (_key, blob) = seal_share(b"x", FUTURE).unwrap();
        let wrong = ShareKey::random().unwrap();
        let r = open_share(&blob, &wrong, FUTURE - 1);
        assert!(matches!(r, Err(CryptoError::DecryptFailed)));
    }

    #[test]
    fn expired_fails() {
        let (key, blob) = seal_share(b"x", PAST).unwrap();
        let r = open_share(&blob, &key, PAST + 1);
        assert!(matches!(r, Err(CryptoError::DecryptFailed)));
    }

    #[test]
    fn tampered_expires_at_fails() {
        let (key, mut blob) = seal_share(b"x", FUTURE).unwrap();
        blob.expires_at += 1; // 改 1 秒 → AAD 变 → 解密失败
        let r = open_share(&blob, &key, FUTURE - 1);
        assert!(matches!(r, Err(CryptoError::DecryptFailed)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (key, mut blob) = seal_share(b"hello world", FUTURE).unwrap();
        let n = blob.ciphertext.len();
        blob.ciphertext[n / 2] ^= 0x01;
        let r = open_share(&blob, &key, FUTURE - 1);
        assert!(matches!(r, Err(CryptoError::DecryptFailed)));
    }

    #[test]
    fn empty_plaintext_rejected() {
        let r = seal_share(b"", FUTURE);
        assert!(matches!(r, Err(CryptoError::InvalidArgument(_))));
    }

    #[test]
    fn two_seals_produce_different_keys_and_nonces() {
        let (k1, b1) = seal_share(b"x", FUTURE).unwrap();
        let (k2, b2) = seal_share(b"x", FUTURE).unwrap();
        assert_ne!(k1.expose_secret(), k2.expose_secret());
        assert_ne!(b1.nonce, b2.nonce);
        assert_ne!(b1.ciphertext, b2.ciphertext);
    }

    #[test]
    fn key_encode_decode_round_trip() {
        let key = ShareKey::random().unwrap();
        let s = key.encode();
        assert!(s.starts_with("RKS1-"));
        let parsed = ShareKey::parse(&s).unwrap();
        assert_eq!(parsed.expose_secret(), key.expose_secret());
    }

    #[test]
    fn key_parse_tolerates_lowercase_and_extra_spaces() {
        let key = ShareKey::random().unwrap();
        let s = key.encode();
        let messy = format!("  {}  ", s.to_ascii_lowercase());
        let parsed = ShareKey::parse(&messy).unwrap();
        assert_eq!(parsed.expose_secret(), key.expose_secret());
    }

    #[test]
    fn key_parse_corrects_i_l_o_confusables() {
        // 用户把 1 输成 I / L,把 0 输成 O 应自动纠正(只动正文,不动 RKS1 前缀)
        let key_bytes = [0x42u8; SymmetricKey::LEN];
        let canonical = ShareKey::from_bytes(key_bytes);
        let s = canonical.encode();
        let prefix_len = KEY_PREFIX.len() + 1; // 含分隔符 '-'
        let (head, body) = s.split_at(prefix_len);
        let messed_body = body.replacen('1', "I", 1).replacen('0', "O", 1);
        let confusing = format!("{head}{messed_body}");
        let parsed = ShareKey::parse(&confusing).unwrap();
        assert_eq!(parsed.expose_secret(), &key_bytes);
    }

    #[test]
    fn key_parse_rejects_missing_prefix() {
        let bad = "NOPREFIX-AAAAA-BBBBB";
        assert!(matches!(
            ShareKey::parse(bad),
            Err(CryptoError::InvalidArgument(_))
        ));
    }

    #[test]
    fn key_parse_rejects_corrupted_checksum() {
        let key = ShareKey::random().unwrap();
        let mut s = key.encode();
        // 改最后一个字符(校验和段)
        s.pop();
        s.push('Z');
        assert!(matches!(
            ShareKey::parse(&s),
            Err(CryptoError::InvalidArgument(_))
        ));
    }

    #[test]
    fn key_parse_rejects_wrong_length() {
        // 太短
        let short = "RKS1-AAAAA";
        assert!(ShareKey::parse(short).is_err());
        // 太长
        let long = format!("RKS1-{}", "A".repeat(200));
        assert!(ShareKey::parse(&long).is_err());
    }

    #[test]
    fn blob_text_round_trip() {
        let (_k, blob) = seal_share(b"hello", FUTURE).unwrap();
        let text = blob.encode_text();
        let parsed = ShareBlob::parse_text(&text).unwrap();
        assert_eq!(parsed, blob);
    }

    #[test]
    fn blob_text_rejects_wrong_magic() {
        let r = ShareBlob::parse_text("wrong-magic\nx\nx\nx\n");
        assert!(matches!(r, Err(CryptoError::UnsupportedVersion(_))));
    }

    #[test]
    fn blob_text_rejects_short_body() {
        let r = ShareBlob::parse_text("rootkey-share-v1\n");
        assert!(r.is_err());
    }

    #[test]
    fn aad_bytes_have_fixed_length_and_includes_exp() {
        let aad1 = aad_for(100);
        let aad2 = aad_for(101);
        assert_eq!(aad1.len(), SHARE_AAD_PREFIX.len() + 8);
        assert_eq!(aad2.len(), aad1.len());
        assert_ne!(aad1, aad2);
    }

    #[test]
    fn debug_does_not_leak_key_bytes() {
        let key = ShareKey::from_bytes([0x42; SymmetricKey::LEN]);
        let s = format!("{:?}", key);
        assert!(s.contains("redacted"));
        assert!(!s.contains("42 42 42"));
    }

    /// CROCKFORD 字母表必须无 I L O U,与文档约定一致。
    #[test]
    fn crockford_alphabet_excludes_ilou() {
        assert!(!CROCKFORD_ALPHABET.contains(&b'I'));
        assert!(!CROCKFORD_ALPHABET.contains(&b'L'));
        assert!(!CROCKFORD_ALPHABET.contains(&b'O'));
        assert!(!CROCKFORD_ALPHABET.contains(&b'U'));
    }
}
