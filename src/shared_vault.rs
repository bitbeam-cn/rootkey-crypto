//! ADR-003 共享 vault 加密原语:X25519 sealed_box + per-recipient wrapped key。
//!
//! ## sealed_box 协议(自实现,无 NaCl 依赖)
//!
//! 给 recipient pubkey `rpk` 发 32B `shared_vault_key`:
//!
//! ```text
//! 1. (esk, epk) = X25519 ephemeral keypair  (32B sk + 32B pk)
//! 2. shared    = X25519(esk, rpk)              (32B)
//! 3. nonce     = BLAKE3(domain || epk || rpk)[..24]   (24B)
//! 4. ct        = XChaCha20-Poly1305(key=shared, nonce, aad=domain, msg=key)
//! 5. output    = epk(32B) || ct(48B = 32 + 16 tag)
//! ```
//!
//! Open(recipient 用 rsk):
//!
//! ```text
//! 1. epk = output[..32];  ct = output[32..]
//! 2. shared = X25519(rsk, epk)
//! 3. nonce  = BLAKE3(domain || epk || pk_from(rsk))[..24]
//! 4. msg    = XChaCha20-Poly1305 decrypt(key=shared, nonce, aad=domain, ct)
//! ```
//!
//! - **domain**:固定字节串 `b"root-key/shared-vault-key/v1"`,与其它 sealed
//!   用法隔离;改值需升级 ADR-003 schema 版本
//! - **AEAD**:XChaCha20-Poly1305(同 vault item 加密)— 已有 dep,符合
//!   SECURITY_MODEL "不发明算法" 原则
//! - **nonce 唯一性**:每个 ephemeral keypair fresh 生成 → nonce = H(esk_derived,
//!   rpk) 几乎不可重复(2^192 抗碰撞)
//!
//! ## 模型
//!
//! - **shared_vault_key**:32 字节对称密钥,**不依赖任何用户主密码**。生成 +
//!   存活在 vault owner 的 RAM,通过本模块的 sealed_box 包给每个 recipient。
//! - **per-recipient wrapped_key**:owner 把 shared_vault_key 用 recipient 的
//!   长期 X25519 pubkey 加密成 sealed_box —— 接收方用自己的 X25519 sk 才能
//!   open。每个成员一份独立 wrap;增删成员只动 wrap 列表,vault content 不动。
//!
//! ## 不变量
//!
//! - **N1**:每次 sealed → fresh ephemeral keypair,不重用
//! - **N2**:撤销成员 = 重生 shared_vault_key + 重 wrap 给剩余成员 + 重加密
//!   所有 ItemKey(否则被撤成员用旧 wrap 仍能解旧内容)
//! - **N3**:owner 必须永久持有自己的 sealed wrap
//! - **N4**:X25519 keypair 用户层标记 "identity",生命周期 ≥ vault 本身
//! - **N5**:wrap 数组长度 = recipient 数,无硬上限

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XSecretKey};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CryptoError, Result};
use crate::keys::SymmetricKey;
use crate::random;

/// X25519 pubkey 字节长度。
pub const X25519_PUBLIC_KEY_LEN: usize = 32;
/// X25519 secret key 字节长度。
pub const X25519_SECRET_KEY_LEN: usize = 32;
/// shared_vault_key 字节长度 = SymmetricKey::LEN(32)。
pub const SHARED_VAULT_KEY_LEN: usize = SymmetricKey::LEN;

/// sealed_box AAD 域分隔。
const DOMAIN: &[u8] = b"root-key/shared-vault-key/v1";

/// XChaCha20 nonce 长度。
const NONCE_LEN: usize = 24;

/// 长期 identity X25519 keypair。每个用户启用 "共享 vault 能力" 时生成一次,
/// 写本地 + pubkey 通过同步 provider 发布(`identities/<user_id>.json`)。
#[derive(Clone)]
pub struct SharedIdentityKeyPair {
    secret: Zeroizing<[u8; X25519_SECRET_KEY_LEN]>,
    public: [u8; X25519_PUBLIC_KEY_LEN],
}

impl SharedIdentityKeyPair {
    /// 新建一个 keypair。sk 用 OS CSPRNG 取 32B,pubkey 用 X25519 派生。
    pub fn generate() -> Result<Self> {
        let raw = random::bytes::<X25519_SECRET_KEY_LEN>()?;
        let sk = XSecretKey::from(raw);
        let pk = XPublicKey::from(&sk);
        Ok(Self {
            secret: Zeroizing::new(raw),
            public: pk.to_bytes(),
        })
    }

    /// 从已落盘的 sk 字节恢复。pubkey 自动派生。
    pub fn from_secret(secret_bytes: [u8; X25519_SECRET_KEY_LEN]) -> Self {
        let sk = XSecretKey::from(secret_bytes);
        let pk = XPublicKey::from(&sk);
        Self {
            secret: Zeroizing::new(secret_bytes),
            public: pk.to_bytes(),
        }
    }

    /// 公开 pubkey(可发布)。
    pub fn public_key(&self) -> [u8; X25519_PUBLIC_KEY_LEN] {
        self.public
    }

    fn secret_bytes(&self) -> &[u8; X25519_SECRET_KEY_LEN] {
        &self.secret
    }

    /// crate-private:给 identity.rs 的 wrap_with_muk 用,把 X25519 secret seed
    /// 序列化进 64B identity envelope。**绝不**对 crate 外暴露。
    pub(crate) fn expose_secret_for_identity_wrap(&self) -> &[u8; X25519_SECRET_KEY_LEN] {
        self.secret_bytes()
    }
}

impl std::fmt::Debug for SharedIdentityKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedIdentityKeyPair")
            .field("public", &"<32B pk>")
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// 包给单个 recipient 的 sealed_box 字节(epk 32B + ciphertext 32+16=48B)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedSharedKey(pub Vec<u8>);

impl SealedSharedKey {
    /// 期望长度 = 32(epk) + 32(key plaintext) + 16(Poly1305 tag) = 80
    pub const EXPECTED_LEN: usize = 32 + SHARED_VAULT_KEY_LEN + 16;
}

/// 跨 crate 版本(`vault_core` 等下游):返回 `Zeroizing<[u8; 32]>` 而非
/// crate-private `SymmetricKey`,语义与 [`create_shared_vault`] 相同。
pub fn create_shared_vault_bytes(
    recipient_pubkeys: &[[u8; X25519_PUBLIC_KEY_LEN]],
) -> Result<(Zeroizing<[u8; SHARED_VAULT_KEY_LEN]>, Vec<SealedSharedKey>)> {
    let raw = random::bytes::<SHARED_VAULT_KEY_LEN>()?;
    let mut wraps = Vec::with_capacity(recipient_pubkeys.len());
    for pk_bytes in recipient_pubkeys {
        wraps.push(wrap_for_recipient(&raw, pk_bytes)?);
    }
    Ok((Zeroizing::new(raw), wraps))
}

/// 跨 crate 版本:[`unwrap_with_identity`] 的 32B 数组返回变体。
pub fn unwrap_with_identity_bytes(
    sealed: &SealedSharedKey,
    identity: &SharedIdentityKeyPair,
) -> Result<Zeroizing<[u8; SHARED_VAULT_KEY_LEN]>> {
    let key = unwrap_with_identity(sealed, identity)?;
    Ok(Zeroizing::new(*key.expose_secret()))
}

// ===== Shared item AEAD —— 用 shared_vault_key 加解密 item plaintext =====

/// shared item 加密 AAD 的域分隔。
const SHARED_ITEM_DOMAIN: &[u8] = b"root-key/shared-item-blob/v1";

/// 持久化的单条 shared item 密文。结构与 `crypto_core::EncryptedItemBlob` 类似,
/// 但 key 派生路径不同:个人 vault 走 IKEK + per-item ItemKey;shared vault
/// 直接用 `shared_vault_key` 作 AEAD key + 把 shared_vault_id 嵌 AAD 防 cross-vault
/// 复用密文。
///
/// 简化设计权衡(vs 个人 vault):
/// - **不**用 per-item 随机 ItemKey + wrap → 直接 shared_vault_key + nonce 即唯一性
/// - 优点:hard revoke 旋转 shared_vault_key 后,新 ciphertext 自动用新 key,
///   旧密文用旧 key — 调用方决定要不要重加密旧密文(目前 hard revoke 不做)
/// - 取舍:被撤者拿到任一明文都意味着他能解开旧密文(因为 ItemKey 就是
///   shared_vault_key 本身);但他本来就有过 shared_vault_key 副本,这点没削弱
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedSharedItem {
    /// schema 版本。
    pub version: u16,
    /// 密文 + 16B tag(SealedBlob 形式)。
    pub blob: crate::aead::SealedBlob,
}

/// 当前 shared item schema 版本。
pub const SHARED_ITEM_VERSION: u16 = 1;

/// 用 shared_vault_key + shared_vault_id 加密 item plaintext。
///
/// `shared_vault_id` 是 UUID 16B —— 嵌 AAD 防止把 vault A 的 ciphertext 灌到
/// vault B 的目录里能解开(HKDF salt 角色)。
pub fn encrypt_shared_item(
    plaintext: &[u8],
    shared_vault_key: &[u8; SHARED_VAULT_KEY_LEN],
    shared_vault_id: &[u8; 16],
) -> Result<EncryptedSharedItem> {
    let key = SymmetricKey::from_bytes(*shared_vault_key);
    let aad = shared_item_aad(shared_vault_id);
    let blob = crate::aead::seal_blob_external(&key, plaintext, &aad)?;
    Ok(EncryptedSharedItem {
        version: SHARED_ITEM_VERSION,
        blob,
    })
}

/// 用 shared_vault_key + shared_vault_id 解密 item。失败统一返 `DecryptFailed`。
pub fn decrypt_shared_item(
    encrypted: &EncryptedSharedItem,
    shared_vault_key: &[u8; SHARED_VAULT_KEY_LEN],
    shared_vault_id: &[u8; 16],
) -> Result<Zeroizing<Vec<u8>>> {
    if encrypted.version != SHARED_ITEM_VERSION {
        return Err(CryptoError::UnsupportedVersion(encrypted.version));
    }
    let key = SymmetricKey::from_bytes(*shared_vault_key);
    let aad = shared_item_aad(shared_vault_id);
    crate::aead::open_blob_external(&key, &encrypted.blob, &aad)
}

fn shared_item_aad(shared_vault_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SHARED_ITEM_DOMAIN.len() + 16);
    aad.extend_from_slice(SHARED_ITEM_DOMAIN);
    aad.extend_from_slice(shared_vault_id);
    aad
}

/// 新建一个 shared vault — 生成对称 key,给初始 N 个 recipient 各自做一份
/// sealed wrap。返回 (key, wraps)。
pub fn create_shared_vault(
    recipient_pubkeys: &[[u8; X25519_PUBLIC_KEY_LEN]],
) -> Result<(SymmetricKey, Vec<SealedSharedKey>)> {
    let raw = random::bytes::<SHARED_VAULT_KEY_LEN>()?;
    let key = SymmetricKey::from_bytes(raw);
    let mut wraps = Vec::with_capacity(recipient_pubkeys.len());
    for pk_bytes in recipient_pubkeys {
        wraps.push(wrap_for_recipient(key.expose_secret(), pk_bytes)?);
    }
    Ok((key, wraps))
}

/// 用 recipient pubkey 把 shared_vault_key 包装成 sealed_box。
pub fn wrap_for_recipient(
    shared_vault_key: &[u8; SHARED_VAULT_KEY_LEN],
    recipient_pubkey: &[u8; X25519_PUBLIC_KEY_LEN],
) -> Result<SealedSharedKey> {
    // 1. ephemeral keypair
    let esk_bytes = random::bytes::<X25519_SECRET_KEY_LEN>()?;
    let esk = XSecretKey::from(esk_bytes);
    let epk = XPublicKey::from(&esk).to_bytes();

    // 2. ECDH shared secret
    let rpk = XPublicKey::from(*recipient_pubkey);
    let shared = esk.diffie_hellman(&rpk);

    // 3. nonce = BLAKE3(domain || epk || rpk)[..24]
    let nonce_bytes = derive_nonce(&epk, recipient_pubkey);

    // 4. AEAD encrypt
    let cipher = XChaCha20Poly1305::new_from_slice(shared.as_bytes())
        .map_err(|_| CryptoError::EncryptFailed)?;
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: shared_vault_key,
                aad: DOMAIN,
            },
        )
        .map_err(|_| CryptoError::EncryptFailed)?;

    // 5. output = epk || ct
    let mut out = Vec::with_capacity(32 + ct.len());
    out.extend_from_slice(&epk);
    out.extend_from_slice(&ct);
    Ok(SealedSharedKey(out))
}

/// recipient 用自己的 X25519 sk open sealed,拿回 shared_vault_key。
pub fn unwrap_with_identity(
    sealed: &SealedSharedKey,
    identity: &SharedIdentityKeyPair,
) -> Result<SymmetricKey> {
    if sealed.0.len() < SealedSharedKey::EXPECTED_LEN {
        return Err(CryptoError::DecryptFailed);
    }
    // 1. split epk + ct
    let mut epk_arr = [0u8; X25519_PUBLIC_KEY_LEN];
    epk_arr.copy_from_slice(&sealed.0[..32]);
    let ct = &sealed.0[32..];

    // 2. ECDH
    let rsk = XSecretKey::from(*identity.secret_bytes());
    let epk = XPublicKey::from(epk_arr);
    let shared = rsk.diffie_hellman(&epk);

    // 3. nonce — recipient pubkey 由 identity 自身的 pk 派生
    let rpk = identity.public_key();
    let nonce_bytes = derive_nonce(&epk_arr, &rpk);

    // 4. AEAD decrypt
    let cipher = XChaCha20Poly1305::new_from_slice(shared.as_bytes())
        .map_err(|_| CryptoError::DecryptFailed)?;
    let mut plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: ct,
                aad: DOMAIN,
            },
        )
        .map_err(|_| CryptoError::DecryptFailed)?;

    if plaintext.len() != SHARED_VAULT_KEY_LEN {
        plaintext.zeroize();
        return Err(CryptoError::DecryptFailed);
    }
    let mut raw = [0u8; SHARED_VAULT_KEY_LEN];
    raw.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(SymmetricKey::from_bytes(raw))
}

/// 给现有 shared vault 添加新成员。返回该成员的 sealed wrap,调用方 push 进
/// wraps 列表并发布。
pub fn add_recipient(
    shared_vault_key: &SymmetricKey,
    new_recipient_pubkey: &[u8; X25519_PUBLIC_KEY_LEN],
) -> Result<SealedSharedKey> {
    wrap_for_recipient(shared_vault_key.expose_secret(), new_recipient_pubkey)
}

/// 撤销成员:生成新 shared_vault_key + 重新 wrap 给剩余成员。
/// **调用方**必须用新 key 重 wrap 所有 ItemKey,否则被撤成员用旧 key 仍能解。
pub fn rotate_shared_vault_key(
    remaining_recipient_pubkeys: &[[u8; X25519_PUBLIC_KEY_LEN]],
) -> Result<(SymmetricKey, Vec<SealedSharedKey>)> {
    create_shared_vault(remaining_recipient_pubkeys)
}

fn derive_nonce(epk: &[u8; 32], rpk: &[u8; 32]) -> [u8; NONCE_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    hasher.update(epk);
    hasher.update(rpk);
    let mut nonce = [0u8; NONCE_LEN];
    let hash = hasher.finalize();
    nonce.copy_from_slice(&hash.as_bytes()[..NONCE_LEN]);
    nonce
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keypair_pubkey_matches_secret() {
        let kp = SharedIdentityKeyPair::generate().unwrap();
        let kp2 = SharedIdentityKeyPair::from_secret(*kp.secret_bytes());
        assert_eq!(kp.public_key(), kp2.public_key());
    }

    #[test]
    fn wrap_and_unwrap_round_trip() {
        let bob = SharedIdentityKeyPair::generate().unwrap();
        let (key, wraps) = create_shared_vault(&[bob.public_key()]).unwrap();
        assert_eq!(wraps[0].0.len(), SealedSharedKey::EXPECTED_LEN);
        let unwrapped = unwrap_with_identity(&wraps[0], &bob).unwrap();
        assert_eq!(key.expose_secret(), unwrapped.expose_secret());
    }

    #[test]
    fn wrong_recipient_cannot_unwrap() {
        let bob = SharedIdentityKeyPair::generate().unwrap();
        let eve = SharedIdentityKeyPair::generate().unwrap();
        let (_key, wraps) = create_shared_vault(&[bob.public_key()]).unwrap();
        let r = unwrap_with_identity(&wraps[0], &eve);
        assert!(matches!(r, Err(CryptoError::DecryptFailed)));
    }

    #[test]
    fn multi_recipient_each_gets_own_wrap() {
        let bob = SharedIdentityKeyPair::generate().unwrap();
        let carol = SharedIdentityKeyPair::generate().unwrap();
        let dad = SharedIdentityKeyPair::generate().unwrap();
        let (key, wraps) = create_shared_vault(&[
            bob.public_key(),
            carol.public_key(),
            dad.public_key(),
        ])
        .unwrap();
        assert_eq!(wraps.len(), 3);
        assert_ne!(wraps[0], wraps[1]);
        assert_ne!(wraps[1], wraps[2]);
        let k_bob = unwrap_with_identity(&wraps[0], &bob).unwrap();
        let k_carol = unwrap_with_identity(&wraps[1], &carol).unwrap();
        let k_dad = unwrap_with_identity(&wraps[2], &dad).unwrap();
        assert_eq!(k_bob.expose_secret(), key.expose_secret());
        assert_eq!(k_carol.expose_secret(), key.expose_secret());
        assert_eq!(k_dad.expose_secret(), key.expose_secret());
    }

    #[test]
    fn cross_unwrap_fails() {
        let bob = SharedIdentityKeyPair::generate().unwrap();
        let carol = SharedIdentityKeyPair::generate().unwrap();
        let (_, wraps) = create_shared_vault(&[
            bob.public_key(),
            carol.public_key(),
        ])
        .unwrap();
        let r = unwrap_with_identity(&wraps[1], &bob);
        assert!(matches!(r, Err(CryptoError::DecryptFailed)));
    }

    #[test]
    fn shared_item_encrypt_decrypt_roundtrip() {
        let key: [u8; SHARED_VAULT_KEY_LEN] = [42; 32];
        let vault_id: [u8; 16] = [0xAB; 16];
        let plaintext = br#"{"title":"GitHub","username":"alice","password":"hunter2"}"#;

        let encrypted = encrypt_shared_item(plaintext, &key, &vault_id).unwrap();
        let decrypted = decrypt_shared_item(&encrypted, &key, &vault_id).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn shared_item_wrong_vault_id_fails() {
        let key: [u8; SHARED_VAULT_KEY_LEN] = [42; 32];
        let vault_a: [u8; 16] = [0x01; 16];
        let vault_b: [u8; 16] = [0x02; 16];

        let encrypted = encrypt_shared_item(b"secret", &key, &vault_a).unwrap();
        // 跨 vault 灌密文 → AAD 不匹配 → DecryptFailed
        let r = decrypt_shared_item(&encrypted, &key, &vault_b);
        assert!(matches!(r, Err(CryptoError::DecryptFailed)));
    }

    #[test]
    fn shared_item_wrong_key_fails() {
        let key_a: [u8; SHARED_VAULT_KEY_LEN] = [42; 32];
        let key_b: [u8; SHARED_VAULT_KEY_LEN] = [99; 32];
        let vault_id: [u8; 16] = [0xAB; 16];

        let encrypted = encrypt_shared_item(b"secret", &key_a, &vault_id).unwrap();
        let r = decrypt_shared_item(&encrypted, &key_b, &vault_id);
        assert!(matches!(r, Err(CryptoError::DecryptFailed)));
    }

    #[test]
    fn shared_item_unsupported_version_rejected() {
        let key: [u8; SHARED_VAULT_KEY_LEN] = [42; 32];
        let vault_id: [u8; 16] = [0xAB; 16];
        let mut encrypted = encrypt_shared_item(b"x", &key, &vault_id).unwrap();
        encrypted.version = 99;
        let r = decrypt_shared_item(&encrypted, &key, &vault_id);
        assert!(matches!(r, Err(CryptoError::UnsupportedVersion(99))));
    }

    #[test]
    fn shared_item_two_encrypts_produce_different_ciphertext() {
        let key: [u8; SHARED_VAULT_KEY_LEN] = [42; 32];
        let vault_id: [u8; 16] = [0xAB; 16];
        let plaintext = b"same plaintext both times";

        let e1 = encrypt_shared_item(plaintext, &key, &vault_id).unwrap();
        let e2 = encrypt_shared_item(plaintext, &key, &vault_id).unwrap();
        // Nonce 随机 → 密文不同
        assert_ne!(e1.blob, e2.blob);
        // 但都能解出原文
        let d1 = decrypt_shared_item(&e1, &key, &vault_id).unwrap();
        let d2 = decrypt_shared_item(&e2, &key, &vault_id).unwrap();
        assert_eq!(&d1[..], plaintext);
        assert_eq!(&d2[..], plaintext);
    }

    #[test]
    fn add_recipient_yields_extra_wrap() {
        let bob = SharedIdentityKeyPair::generate().unwrap();
        let carol = SharedIdentityKeyPair::generate().unwrap();
        let (key, mut wraps) = create_shared_vault(&[bob.public_key()]).unwrap();
        wraps.push(add_recipient(&key, &carol.public_key()).unwrap());
        assert_eq!(wraps.len(), 2);
        let k = unwrap_with_identity(&wraps[1], &carol).unwrap();
        assert_eq!(k.expose_secret(), key.expose_secret());
    }

    #[test]
    fn rotate_yields_new_key() {
        let bob = SharedIdentityKeyPair::generate().unwrap();
        let (old_key, _) = create_shared_vault(&[bob.public_key()]).unwrap();
        let (new_key, new_wraps) =
            rotate_shared_vault_key(&[bob.public_key()]).unwrap();
        assert_ne!(old_key.expose_secret(), new_key.expose_secret());
        let k = unwrap_with_identity(&new_wraps[0], &bob).unwrap();
        assert_eq!(k.expose_secret(), new_key.expose_secret());
    }

    #[test]
    fn truncated_sealed_box_fails() {
        let bob = SharedIdentityKeyPair::generate().unwrap();
        let (_, wraps) = create_shared_vault(&[bob.public_key()]).unwrap();
        let mut bad = wraps[0].clone();
        bad.0.truncate(bad.0.len() - 1);
        assert!(matches!(
            unwrap_with_identity(&bad, &bob),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn tampered_sealed_box_fails() {
        let bob = SharedIdentityKeyPair::generate().unwrap();
        let (_, wraps) = create_shared_vault(&[bob.public_key()]).unwrap();
        let mut bad = wraps[0].clone();
        let last = bad.0.len() - 1;
        bad.0[last] ^= 0x01;
        assert!(matches!(
            unwrap_with_identity(&bad, &bob),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn two_seals_for_same_recipient_differ() {
        let bob = SharedIdentityKeyPair::generate().unwrap();
        let key = SymmetricKey::from_bytes([0x42; SHARED_VAULT_KEY_LEN]);
        let w1 = wrap_for_recipient(key.expose_secret(), &bob.public_key()).unwrap();
        let w2 = wrap_for_recipient(key.expose_secret(), &bob.public_key()).unwrap();
        // fresh ephemeral keypair → 不同 sealed
        assert_ne!(w1, w2);
        // 但都能 unwrap 同一 key
        let k1 = unwrap_with_identity(&w1, &bob).unwrap();
        let k2 = unwrap_with_identity(&w2, &bob).unwrap();
        assert_eq!(k1.expose_secret(), key.expose_secret());
        assert_eq!(k2.expose_secret(), key.expose_secret());
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let kp = SharedIdentityKeyPair::from_secret([0x42; X25519_SECRET_KEY_LEN]);
        let s = format!("{:?}", kp);
        assert!(s.contains("redacted"));
    }

    #[test]
    fn empty_recipient_list_creates_key_no_wraps() {
        let (key, wraps) = create_shared_vault(&[]).unwrap();
        assert_eq!(wraps.len(), 0);
        assert_ne!(key.expose_secret(), &[0u8; SHARED_VAULT_KEY_LEN]);
    }

    #[test]
    fn sealed_size_is_exact() {
        let bob = SharedIdentityKeyPair::generate().unwrap();
        let key = SymmetricKey::from_bytes([0x33; SHARED_VAULT_KEY_LEN]);
        let w = wrap_for_recipient(key.expose_secret(), &bob.public_key()).unwrap();
        assert_eq!(w.0.len(), SealedSharedKey::EXPECTED_LEN);
        assert_eq!(SealedSharedKey::EXPECTED_LEN, 80);
    }
}
