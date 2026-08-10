//! 加密原语的标准测试向量 + RootKey 自身派生流程的固定向量。
//!
//! 这些测试不应随时间变化 —— 一旦失败,要么是依赖 crate 升级改了行为,
//! 要么是我们改了派生流程。两者都需要走 ADR + vault 版本升级流程。

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

use crypto_core::{
    decrypt_item, derive_muk, encrypt_item, kdf::KdfAlgorithm, unlock_vault, KdfParams,
    MasterUnlockKey,
};

// ---------- Argon2id 自一致性向量(纯 RustCrypto crate 行为,与我们 ADR-001 后
// derive_muk 不用 secret 的事实独立)----------

#[test]
fn argon2id_basic_is_stable() {
    let password = [0x01u8; 32];
    let salt = [0x02u8; 16];

    let params = Params::new(32, 3, 4, Some(32)).unwrap();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    argon.hash_password_into(&password, &salt, &mut a).unwrap();
    argon.hash_password_into(&password, &salt, &mut b).unwrap();
    assert_eq!(a, b, "deterministic");
    assert_ne!(a, [0u8; 32], "non-trivial output");
}

// ---------- XChaCha20-Poly1305 IETF draft §A.3.1 风格向量 ----------

#[test]
fn xchacha20poly1305_round_trip_with_known_inputs() {
    let key_bytes: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    let nonce_bytes: [u8; 24] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    ];
    let aad: &[u8] = &[
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .unwrap();
    assert_eq!(ciphertext.len(), plaintext.len() + 16);

    let recovered = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .unwrap();
    assert_eq!(recovered, plaintext);

    let bad_aad: Vec<u8> = aad.iter().map(|b| b ^ 0x01).collect();
    assert!(cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ciphertext,
                aad: &bad_aad,
            },
        )
        .is_err());
}

// ---------- RootKey `derive_muk` 固定向量(ADR-001:无 SK)----------
//
// 锁定特定输入 → 特定输出。这是我们与历史 vault 的契约:改算法 / 归一化 /
// 参数序列化 → 必须升级 vault 格式版本号。

const FIXED_PASSWORD: &str = "correct horse battery staple";
const FIXED_SALT: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

// OWASP Password Storage Cheat Sheet 2024 第二档下限:m=19 MiB / t=2 / p=1。
// `KdfParams::validate` 强制不低于该档,任何更低参数都被拒绝。
fn fixed_params() -> KdfParams {
    KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        memory_kib: 19 * 1024,
        time_cost: 2,
        parallelism: 1,
        salt: FIXED_SALT,
    }
}

#[test]
fn derive_muk_fixed_input_is_deterministic() {
    let params = fixed_params();
    let a = derive_muk(FIXED_PASSWORD, &params).unwrap();
    let b = derive_muk(FIXED_PASSWORD, &params).unwrap();
    assert_eq!(a.expose_secret(), b.expose_secret());
}

#[test]
fn derive_muk_fixed_input_locked_hex() {
    let muk: MasterUnlockKey = derive_muk(FIXED_PASSWORD, &fixed_params()).unwrap();

    // 期望值由当前实现 + 当前 argon2 crate 版本生成。一旦失败,要么依赖升级改了
    // Argon2id 输出(极少见),要么我们的派生管线改动 — 必须升级
    // EncryptedKeySet::version 并写迁移路径。
    const EXPECTED_HEX: &str = include_str!("vectors/derive_muk_fixed.hex");
    let expected = EXPECTED_HEX.trim();

    assert_eq!(hex::encode(muk.expose_secret()), expected);
}

// ---------- 全链路:固定密码(ADR-001)----------

#[test]
fn end_to_end_with_fixed_password() {
    let created = crypto_core::create_vault_keys("p@ssw0rd!").unwrap();
    let blob = encrypt_item(b"hello world", &[9u8; 16], &created.unlocked).unwrap();

    let unlocked = unlock_vault("p@ssw0rd!", &created.encrypted).unwrap();
    let decrypted = decrypt_item(&blob, &[9u8; 16], &unlocked).unwrap();
    assert_eq!(decrypted.as_slice(), b"hello world");

    assert!(unlock_vault("p@ssw0rd?", &created.encrypted).is_err());
}
