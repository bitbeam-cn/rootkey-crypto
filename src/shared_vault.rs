//! ADR-003 共享 vault 加密原语:sealed box + per-recipient wrapped key。
//!
//! ## sealed_box 协议(**不自实现**,直接用 `dryoc` 的 libsodium `crypto_box_seal`)
//!
//! 之前这里手搓了 X25519 ECDH + BLAKE3 KDF + XChaCha20 的密封构造。现在改成
//! 直接调 [`dryoc::dryocbox::DryocBox`] 的 `seal`/`unseal`(= libsodium
//! `crypto_box_seal`,纯 Rust、与 C libsodium 逐字节兼容、按 libsodium 测试
//! 向量验证):X25519 密钥派生 + XSalsa20-Poly1305 + 匿名 ephemeral 发送方。
//! ephemeral keypair、nonce = BLAKE2b(epk‖rpk)、低阶点检查(crypto_scalarmult
//! 拒全零输出)全部在库内正确实现,不再由本 crate 拼装。
//!
//! wire 格式 = `ephemeral_pk(32) || box(mac 16 + ciphertext)`,与 libsodium
//! 密封盒兼容;对 32B 的 shared_vault_key 恰好 80 字节。
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
//! - **N2**:撤销成员 = 重生 shared_vault_key + 重 wrap 给剩余成员。这保护
//!   **撤销之后**新增/更新的条目;**撤销前的旧密文用旧 key 加密,仍可被留有
//!   旧密文与旧 key 副本的被撤成员解开** —— 这是团队共享库的固有模型(与
//!   1Password/Bitwarden 组织库一致),不是缺陷。若业务要"硬撤销"到旧内容
//!   也不可读,须由调用方额外用新 key 重加密所有历史条目(当前不做,见
//!   [`EncryptedSharedItem`] 的取舍说明)。
//! - **N3**:owner 必须永久持有自己的 sealed wrap
//! - **N4**:X25519 keypair 用户层标记 "identity",生命周期 ≥ vault 本身
//! - **N5**:wrap 数组长度 = recipient 数,无硬上限

use dryoc::dryocbox::{DryocBox, KeyPair, PublicKey, SecretKey};
use dryoc::types::ByteArray;
use serde::{Deserialize, Serialize};
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

/// 长期 identity X25519 keypair。每个用户启用 "共享 vault 能力" 时生成一次,
/// 写本地 + pubkey 通过同步 provider 发布(`identities/<user_id>.json`)。
/// 密钥派生与密封盒运算全部委托给 [`dryoc`](libsodium crypto_box),本类型只
/// 持有原始字节 + 提供构造。
#[derive(Clone)]
pub struct SharedIdentityKeyPair {
    secret: Zeroizing<[u8; X25519_SECRET_KEY_LEN]>,
    public: [u8; X25519_PUBLIC_KEY_LEN],
}

impl SharedIdentityKeyPair {
    /// 新建一个 keypair。用 dryoc(libsodium crypto_box)生成 X25519 keypair。
    pub fn generate() -> Result<Self> {
        let kp = KeyPair::gen();
        Ok(Self {
            secret: Zeroizing::new(*kp.secret_key.as_array()),
            public: *kp.public_key.as_array(),
        })
    }

    /// 从已落盘的 sk 字节恢复。pubkey 由 dryoc 从 secret 派生(X25519 basepoint mult)。
    pub fn from_secret(secret_bytes: [u8; X25519_SECRET_KEY_LEN]) -> Self {
        let kp = KeyPair::from_secret_key(SecretKey::from(secret_bytes));
        Self {
            secret: Zeroizing::new(secret_bytes),
            public: *kp.public_key.as_array(),
        }
    }

    /// 公开 pubkey(可发布)。
    pub fn public_key(&self) -> [u8; X25519_PUBLIC_KEY_LEN] {
        self.public
    }

    fn secret_bytes(&self) -> &[u8; X25519_SECRET_KEY_LEN] {
        &self.secret
    }

    /// 构造 dryoc keypair 供密封盒 unseal 使用(public 由 secret 现场派生)。
    fn dryoc_keypair(&self) -> KeyPair {
        KeyPair::from_secret_key(SecretKey::from(*self.secret))
    }

    /// crate-private:给 identity.rs 的 wrap_with_vault 用,把 X25519 secret seed
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

/// 密封盒格式版本(1 字节前缀)。为后量子 hybrid / 格式演进留门:
/// 未来上 X25519+ML-KEM 会大幅改变 wire,靠此字节区分老/新格式。
pub const SEALED_FORMAT_V1: u8 = 1;

/// 包给单个 recipient 的 sealed_box 字节:`version(1B) || libsodium sealed box`。
/// libsodium 部分 = epk 32B + ciphertext(32 明文 + 16 tag)= 80。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedSharedKey(pub Vec<u8>);

impl SealedSharedKey {
    /// 期望长度 = 1(版本) + 32(epk) + 32(key) + 16(tag) = 81。
    pub const EXPECTED_LEN: usize = 1 + 32 + SHARED_VAULT_KEY_LEN + 16;
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

/// 用 recipient pubkey 把 shared_vault_key 密封成 libsodium sealed box。
///
/// 直接调 dryoc 的 `DryocBox::seal`:ephemeral keypair / nonce 派生 / 低阶点
/// 检查全在库内。输出 = `to_vec()` 的 libsodium 兼容字节。
pub fn wrap_for_recipient(
    shared_vault_key: &[u8; SHARED_VAULT_KEY_LEN],
    recipient_pubkey: &[u8; X25519_PUBLIC_KEY_LEN],
) -> Result<SealedSharedKey> {
    // dryoc 1.0 的 seal 会拒绝低阶点公钥(crypto_box_detached 返回错误),
    // 无需再手动 guard —— 交给库处理。
    let recipient_pk = PublicKey::from(*recipient_pubkey);
    let sealed = DryocBox::seal_to_vecbox(shared_vault_key.as_slice(), &recipient_pk)
        .map_err(|_| CryptoError::EncryptFailed)?;
    let body = sealed.to_vec();
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(SEALED_FORMAT_V1); // 版本前缀,为格式演进留门
    out.extend_from_slice(&body);
    Ok(SealedSharedKey(out))
}

/// recipient 用自己的 X25519 keypair open sealed box,拿回 shared_vault_key。
pub fn unwrap_with_identity(
    sealed: &SealedSharedKey,
    identity: &SharedIdentityKeyPair,
) -> Result<SymmetricKey> {
    // 剥版本前缀:目前只认 v1。
    if sealed.0.first() != Some(&SEALED_FORMAT_V1) {
        return Err(CryptoError::DecryptFailed);
    }
    let dbox =
        DryocBox::from_sealed_bytes(&sealed.0[1..]).map_err(|_| CryptoError::DecryptFailed)?;
    let keypair = identity.dryoc_keypair();
    let mut plaintext = dbox
        .unseal_to_vec(&keypair)
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
    fn wrong_version_prefix_rejected() {
        let bob = SharedIdentityKeyPair::generate().unwrap();
        let (_key, wraps) = create_shared_vault(&[bob.public_key()]).unwrap();
        let mut bad = wraps[0].clone();
        bad.0[0] = 0xFF; // 非 v1 版本
        assert!(matches!(
            unwrap_with_identity(&bad, &bob),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn low_order_recipient_pubkey_rejected() {
        // 全零是 Curve25519 的低阶点:ECDH 输出恒为全零、was_contributory 为假。
        // 恶意 provider 若把成员公钥换成这种点,wrap 必须直接失败而非产出可预测密文。
        let key = SymmetricKey::from_bytes([0x42; SHARED_VAULT_KEY_LEN]);
        let low_order = [0u8; X25519_PUBLIC_KEY_LEN];
        let r = wrap_for_recipient(key.expose_secret(), &low_order);
        assert!(matches!(r, Err(CryptoError::EncryptFailed)));
    }

    #[test]
    fn sealed_size_is_exact() {
        let bob = SharedIdentityKeyPair::generate().unwrap();
        let key = SymmetricKey::from_bytes([0x33; SHARED_VAULT_KEY_LEN]);
        let w = wrap_for_recipient(key.expose_secret(), &bob.public_key()).unwrap();
        assert_eq!(w.0.len(), SealedSharedKey::EXPECTED_LEN);
        assert_eq!(SealedSharedKey::EXPECTED_LEN, 81);
        assert_eq!(w.0[0], SEALED_FORMAT_V1);
    }
}
