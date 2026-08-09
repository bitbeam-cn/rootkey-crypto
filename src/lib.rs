//! RootKey 加密核心。
//!
//! 设计文档:
//! - [`docs/SECURITY_MODEL.md`](https://github.com/bitbeam-cn/rootkey-crypto/blob/main/docs/SECURITY_MODEL.md)
//! - [`docs/VAULT_FORMAT.md`](https://github.com/bitbeam-cn/rootkey-crypto/blob/main/docs/VAULT_FORMAT.md)
//! - ADR-001:移除 Secret Key 双因子,采用单一主密码模型
//!
//! ## 密钥层次(ADR-001 之后)
//!
//! ```text
//! Master Password(用户记忆,UI 强制 ≥ 12 位 + zxcvbn score ≥ 3)
//!         │  Argon2id(P=password, S=salt 32B, memory 128 MiB)
//!         ▼
//!     MUK  (Master Unlock Key)
//!         │  AES-256-GCM
//!         ▼
//!     KEK  (Key Encryption Key)
//!         │  AES-256-GCM
//!         ▼
//!     VMK  (Vault Master Key)
//!         │  AES-256-GCM
//!         ▼
//!     IKEK (Item KEK)
//!         │  AES-256-GCM(per item)
//!         ▼
//!  ItemKey (per item)
//!         │  XChaCha20-Poly1305
//!         ▼
//!  Item Plaintext
//! ```
//!
//! 详细参数见 [`kdf`] 与 [`aead`]。
//!
//! ## 入门
//!
//! ```no_run
//! use crypto_core::{create_vault_keys, encrypt_item, decrypt_item};
//!
//! let vault = create_vault_keys("hunter2 — but stronger pls")?;
//!
//! let blob = encrypt_item(b"my login data", &vault.unlocked)?;
//! let plain = decrypt_item(&blob, &vault.unlocked)?;
//! assert_eq!(plain.as_slice(), b"my login data");
//! # Ok::<_, crypto_core::CryptoError>(())
//! ```

#![warn(missing_docs)]
#![warn(unsafe_code)]

pub mod account;
pub mod aead;
pub mod error;
pub mod export;
pub mod identity;
pub mod item;
pub mod kdf;
pub mod keys;
pub mod random;
pub mod share;
pub mod shared_vault;
pub mod signing;
pub mod vault;

pub use account::{
    change_account_password, create_account, create_vault_under_account,
    reset_password_with_recovery_key, setup_recovery_key, unlock_account_with_recovery_key,
    enable_account_biometric, unlock_account, unlock_account_via_biometric,
    unlock_account_vault, AccountBiometricEnvelope, AccountBiometricSetup, AccountKeySet,
    AccountKeys, AccountVaultEntry, UnlockedAccount, VaultKeySlot, VaultUnderAccount,
    ACCOUNT_FORMAT_VERSION,
};
pub use error::{CryptoError, Result};
pub use export::{open_with_password, seal_with_password, EncryptedBundle, EXPORT_MAGIC};
pub use item::{decrypt_item, encrypt_item, EncryptedItemBlob};
pub use kdf::{
    derive_muk, KdfAlgorithm, KdfParams, DEFAULT_MEMORY_KIB, DEFAULT_PARALLELISM, DEFAULT_TIME_COST,
};
pub use keys::{ItemKekKey, ItemKey, KeyEncryptionKey, MasterUnlockKey, VaultMasterKey};
pub use identity::{fingerprint_from_pubkeys, Identity, WrappedIdentity, ED25519_SEED_LEN};
pub use shared_vault::{
    decrypt_shared_item, encrypt_shared_item, EncryptedSharedItem, SHARED_ITEM_VERSION,
};
pub use share::{open_share, seal_share, ShareBlob, ShareKey};
pub use signing::{Signature, SigningKey, VerifyingKey};
pub use vault::{
    change_master_password, create_vault_keys, enable_biometric_unlock, rotate_vault_key,
    unlock_vault, unlock_via_biometric, unwrap_signing_seed, wrap_signing_seed,
    BiometricEnvelope, BiometricUnlockSetup, EncryptedKeySet, UnlockedVault, VaultKeySet,
    KEYSET_FORMAT_VERSION,
};
pub use aead::WrappedKey;

/// 当前 crypto_core 的版本字符串。
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
