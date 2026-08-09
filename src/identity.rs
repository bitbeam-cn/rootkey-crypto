//! ADR-003 Phase B 第一步:本地身份(identity)管理。
//!
//! 每个启用了"共享 vault 能力"的用户在自己设备上有一对长期身份密钥:
//!
//! - **X25519 keypair**:用于 `shared_vault.rs` 的 sealed_box wrap/unwrap
//!   (其它管理员把 `shared_vault_key` 加密发给我,我用 `x25519_sk` 解开)
//! - **Ed25519 keypair**:用于签名 `members.json` / `identities/<user>.json`
//!   (admin 改 members 时签;成员验签确认 members.json 真由 admin 改)
//!
//! 两套 keypair 一起本地落盘(`identity.secret.enc`),由主密码派生的 MUK
//! 子密钥包装。新设备 `bootstrap_vault_from_sync` 走完后立即解 `identity.secret.enc`
//! 拿到 sk,无需另外 KDF。
//!
//! ## 文件格式(`identity.secret.enc`)
//!
//! 64 字节明文 plaintext 经 XChaCha20-Poly1305 加密:
//!
//! ```text
//! plaintext = x25519_seed(32B) || ed25519_seed(32B)
//! key       = MUK
//! aad       = b"root-key/identity-secret/v1" || account_id_bytes(16B)
//! envelope  = SealedBlob { nonce(24B), ciphertext(64+16=80B) }
//! ```
//!
//! ## fingerprint
//!
//! UI 在加成员前必须显示对方的 fingerprint 让本人带外校验(ADR-003 §"MITM
//! 防御"):8 组 4 hex 字符,来自 `BLAKE3(x25519_pk || ed25519_pk)[..16]`。

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::aead::{open_blob, seal_blob, SealedBlob};
use crate::error::{CryptoError, Result};
use crate::keys::MasterUnlockKey;
use crate::shared_vault::{SharedIdentityKeyPair, X25519_PUBLIC_KEY_LEN, X25519_SECRET_KEY_LEN};
use crate::signing::{SigningKey, VerifyingKey};

/// AAD 域分隔(identity 加密专用,与其它 AEAD 用法隔离)。
const IDENTITY_DOMAIN: &[u8] = b"root-key/identity-secret/v1";

/// Ed25519 seed 字节长度(SigningKey::expose_seed 返回 32B)。
pub const ED25519_SEED_LEN: usize = 32;

/// 完整本地身份 —— X25519 + Ed25519 两把 keypair。
///
/// `Drop` 时 X25519 secret 走 [`SharedIdentityKeyPair`] 内部的 `Zeroizing`;
/// Ed25519 走 [`SigningKey`] 内部的 `ed25519-dalek::SigningKey`(zeroize on drop)。
pub struct Identity {
    x25519: SharedIdentityKeyPair,
    ed25519: SigningKey,
}

impl Identity {
    /// 新建一对本地身份。两个 keypair 都用 OS CSPRNG 独立生成。
    pub fn generate() -> Result<Self> {
        Ok(Self {
            x25519: SharedIdentityKeyPair::generate()?,
            ed25519: SigningKey::generate_os()?,
        })
    }

    /// 从已落盘的两个 seed 恢复完整身份。
    pub fn from_seeds(
        x25519_seed: [u8; X25519_SECRET_KEY_LEN],
        ed25519_seed: [u8; ED25519_SEED_LEN],
    ) -> Self {
        Self {
            x25519: SharedIdentityKeyPair::from_secret(x25519_seed),
            ed25519: SigningKey::from_bytes(&ed25519_seed),
        }
    }

    /// X25519 pubkey(可发布)。
    pub fn x25519_public(&self) -> [u8; X25519_PUBLIC_KEY_LEN] {
        self.x25519.public_key()
    }

    /// Ed25519 verifying key(可发布)。
    pub fn ed25519_public(&self) -> VerifyingKey {
        self.ed25519.verifying_key()
    }

    /// 内部:暴露 X25519 keypair(给 [`crate::shared_vault::unwrap_with_identity`] 用)。
    pub fn x25519_keypair(&self) -> &SharedIdentityKeyPair {
        &self.x25519
    }

    /// 内部:暴露 Ed25519 signing key(给 members.json / identities/* 签名用)。
    pub fn ed25519_signer(&self) -> &SigningKey {
        &self.ed25519
    }

    /// UI 带外校验用的 fingerprint —— 8 组 4 hex 字符,空格分隔。
    /// 输入:`BLAKE3(x25519_pk || ed25519_pk)`,取前 16 字节(32 hex char)。
    ///
    /// 例:`"AB12 CD34 EF56 7890 90AB CDEF 1234 5678"`
    pub fn fingerprint(&self) -> String {
        fingerprint_from_pubkeys(&self.x25519_public(), &self.ed25519_public().to_bytes())
    }

    /// 把身份 sk 用 MUK 包装成 [`WrappedIdentity`] —— 调用方落盘。
    ///
    /// `account_id` 必须与 vault 的 account_id 一致,作为 AAD 一部分防 cross-account
    /// 把别人的 identity envelope 灌进来当自己的。
    pub fn wrap_with_muk(
        &self,
        muk: &MasterUnlockKey,
        account_id: &[u8; 16],
    ) -> Result<WrappedIdentity> {
        // 64B plaintext = x25519_seed(32B) || ed25519_seed(32B)
        let mut plaintext = Zeroizing::new(Vec::with_capacity(64));
        plaintext.extend_from_slice(self.x25519.expose_secret_for_identity_wrap());
        plaintext.extend_from_slice(&self.ed25519.expose_seed());

        let aad = identity_aad(account_id);
        let envelope = seal_blob(&muk.0, &plaintext, &aad)?;
        Ok(WrappedIdentity {
            schema_version: WRAPPED_IDENTITY_VERSION,
            envelope,
        })
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("x25519_public", &"<32B pk>")
            .field("ed25519_public", &"<32B pk>")
            .field("secrets", &"<redacted>")
            .finish()
    }
}

/// 当前 wrapped identity schema 版本。
pub const WRAPPED_IDENTITY_VERSION: u16 = 1;

/// 落盘形态 —— `identity.secret.enc` 反序列化目标。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WrappedIdentity {
    /// 当前格式版本(`WRAPPED_IDENTITY_VERSION`)。
    pub schema_version: u16,
    /// XChaCha20-Poly1305 envelope(nonce + 64B+16B tag = 96B)。
    pub envelope: SealedBlob,
}

impl WrappedIdentity {
    /// 用 MUK 解开,返回完整 [`Identity`]。
    ///
    /// 失败情况:
    /// - 错的 MUK / 错的 account_id → `CryptoError::DecryptFailed`
    /// - schema 不认 → `CryptoError::UnsupportedSchema`
    /// - 解开后字节长度不是 64 → `CryptoError::InvalidArgument`
    pub fn unwrap_with_muk(
        &self,
        muk: &MasterUnlockKey,
        account_id: &[u8; 16],
    ) -> Result<Identity> {
        if self.schema_version != WRAPPED_IDENTITY_VERSION {
            return Err(CryptoError::UnsupportedVersion(self.schema_version));
        }
        let aad = identity_aad(account_id);
        let plaintext = open_blob(&muk.0, &self.envelope, &aad)?;
        if plaintext.len() != X25519_SECRET_KEY_LEN + ED25519_SEED_LEN {
            return Err(CryptoError::InvalidArgument(
                "identity plaintext length must be 64 bytes",
            ));
        }
        let mut x25519_seed = [0u8; X25519_SECRET_KEY_LEN];
        x25519_seed.copy_from_slice(&plaintext[..X25519_SECRET_KEY_LEN]);
        let mut ed25519_seed = [0u8; ED25519_SEED_LEN];
        ed25519_seed.copy_from_slice(&plaintext[X25519_SECRET_KEY_LEN..]);
        Ok(Identity::from_seeds(x25519_seed, ed25519_seed))
    }
}

/// 给定 X25519 + Ed25519 公钥,计算 fingerprint(8 组 4 hex 字符,空格分隔)。
///
/// 与 [`Identity::fingerprint`] 等价,但**只需要公钥**,UI 拉远端
/// `identities/<user_id>.json` 后即可显示对方 fingerprint 让本人带外核对。
pub fn fingerprint_from_pubkeys(
    x25519_pk: &[u8; X25519_PUBLIC_KEY_LEN],
    ed25519_pk: &[u8; 32],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(x25519_pk);
    hasher.update(ed25519_pk);
    let hash = hasher.finalize();
    let bytes = &hash.as_bytes()[..16];

    // 16B → 32 hex char → 8 组 ×4 字符,空格分隔
    let mut out = String::with_capacity(32 + 7);
    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 && i % 2 == 0 {
            out.push(' ');
        }
        use std::fmt::Write;
        let _ = write!(&mut out, "{byte:02X}");
    }
    out
}

fn identity_aad(account_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(IDENTITY_DOMAIN.len() + 16);
    aad.extend_from_slice(IDENTITY_DOMAIN);
    aad.extend_from_slice(account_id);
    aad
}

// SharedIdentityKeyPair::expose_secret_for_identity_wrap() 是 crate-private API,
// 见 shared_vault.rs。本模块直接调用,无需 trait 间接桥。

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{derive_muk, KdfParams};

    fn dummy_muk() -> MasterUnlockKey {
        MasterUnlockKey::generate().unwrap()
    }

    fn dummy_account_id() -> [u8; 16] {
        [
            0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
            0x00, 0x00,
        ]
    }

    #[test]
    fn generate_produces_distinct_identities() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        assert_ne!(a.x25519_public(), b.x25519_public());
        assert_ne!(
            a.ed25519_public().to_bytes(),
            b.ed25519_public().to_bytes()
        );
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let identity = Identity::generate().unwrap();
        let muk = dummy_muk();
        let account = dummy_account_id();

        let wrapped = identity.wrap_with_muk(&muk, &account).unwrap();
        let restored = wrapped.unwrap_with_muk(&muk, &account).unwrap();

        assert_eq!(restored.x25519_public(), identity.x25519_public());
        assert_eq!(
            restored.ed25519_public().to_bytes(),
            identity.ed25519_public().to_bytes()
        );
        assert_eq!(restored.fingerprint(), identity.fingerprint());
    }

    #[test]
    fn from_seeds_recovers_same_pubkeys() {
        let identity = Identity::generate().unwrap();
        let x_seed = *identity.x25519.expose_secret_for_identity_wrap();
        let e_seed = identity.ed25519.expose_seed();

        let restored = Identity::from_seeds(x_seed, e_seed);
        assert_eq!(restored.x25519_public(), identity.x25519_public());
        assert_eq!(
            restored.ed25519_public().to_bytes(),
            identity.ed25519_public().to_bytes()
        );
    }

    #[test]
    fn unwrap_with_wrong_muk_fails() {
        let identity = Identity::generate().unwrap();
        let muk_a = dummy_muk();
        let muk_b = dummy_muk();
        let account = dummy_account_id();

        let wrapped = identity.wrap_with_muk(&muk_a, &account).unwrap();
        let err = wrapped.unwrap_with_muk(&muk_b, &account).unwrap_err();
        assert!(matches!(err, CryptoError::DecryptFailed), "got {err:?}");
    }

    #[test]
    fn unwrap_with_wrong_account_id_fails() {
        let identity = Identity::generate().unwrap();
        let muk = dummy_muk();
        let acc_a = dummy_account_id();
        let acc_b: [u8; 16] = [
            0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x55, 0x55,
            0x55, 0x55,
        ];

        let wrapped = identity.wrap_with_muk(&muk, &acc_a).unwrap();
        let err = wrapped.unwrap_with_muk(&muk, &acc_b).unwrap_err();
        assert!(matches!(err, CryptoError::DecryptFailed), "got {err:?}");
    }

    #[test]
    fn schema_mismatch_rejected() {
        let identity = Identity::generate().unwrap();
        let muk = dummy_muk();
        let account = dummy_account_id();

        let mut wrapped = identity.wrap_with_muk(&muk, &account).unwrap();
        wrapped.schema_version = 99;
        let err = wrapped.unwrap_with_muk(&muk, &account).unwrap_err();
        assert!(matches!(err, CryptoError::UnsupportedVersion(99)), "got {err:?}");
    }

    #[test]
    fn tampered_envelope_fails_decrypt() {
        let identity = Identity::generate().unwrap();
        let muk = dummy_muk();
        let account = dummy_account_id();

        let mut wrapped = identity.wrap_with_muk(&muk, &account).unwrap();
        // 翻第一个 ciphertext 字节
        if let Some(b) = wrapped.envelope.ciphertext.first_mut() {
            *b ^= 0xff;
        }
        let err = wrapped.unwrap_with_muk(&muk, &account).unwrap_err();
        assert!(matches!(err, CryptoError::DecryptFailed), "got {err:?}");
    }

    #[test]
    fn fingerprint_has_8_groups_of_4_hex() {
        let identity = Identity::generate().unwrap();
        let fp = identity.fingerprint();
        let groups: Vec<&str> = fp.split(' ').collect();
        assert_eq!(groups.len(), 8, "fingerprint must have 8 groups: {fp}");
        for g in groups {
            assert_eq!(g.len(), 4, "each group is 4 hex chars: {g}");
            assert!(g.chars().all(|c| c.is_ascii_hexdigit()), "hex only: {g}");
        }
    }

    #[test]
    fn fingerprint_stable_across_wrap_unwrap() {
        let identity = Identity::generate().unwrap();
        let fp1 = identity.fingerprint();
        let muk = dummy_muk();
        let account = dummy_account_id();
        let wrapped = identity.wrap_with_muk(&muk, &account).unwrap();
        let restored = wrapped.unwrap_with_muk(&muk, &account).unwrap();
        let fp2 = restored.fingerprint();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_from_pubkeys_matches_identity_fingerprint() {
        let identity = Identity::generate().unwrap();
        let x_pk = identity.x25519_public();
        let e_pk = identity.ed25519_public().to_bytes();
        let fp_via_helper = fingerprint_from_pubkeys(&x_pk, &e_pk);
        assert_eq!(identity.fingerprint(), fp_via_helper);
    }

    #[test]
    fn different_identities_have_different_fingerprints() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let identity = Identity::generate().unwrap();
        let s = format!("{identity:?}");
        assert!(s.contains("redacted"), "debug should redact secrets: {s}");
        assert!(!s.contains("seed"), "debug should not mention seed bytes: {s}");
    }

    #[test]
    fn round_trip_with_real_kdf_muk() {
        // 用真实 derive_muk 路径派生 MUK,验证 KDF 输出形态契合
        let kdf = KdfParams::generate_default().unwrap();
        let muk = derive_muk("test-password-12chars", &kdf).unwrap();
        let identity = Identity::generate().unwrap();
        let account = dummy_account_id();

        let wrapped = identity.wrap_with_muk(&muk, &account).unwrap();
        let restored = wrapped.unwrap_with_muk(&muk, &account).unwrap();
        assert_eq!(restored.x25519_public(), identity.x25519_public());
    }
}
