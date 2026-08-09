//! 标准化测试向量 — 来自 IETF / IRTF / NIST。
//!
//! 这些向量定义了底层加密原语的"对外契约":
//! - **RFC 9106 Appendix A.1** —— Argon2id v1.3 测试向量
//! - **draft-irtf-cfrg-xchacha-03 Appendix A.3.1** —— XChaCha20-Poly1305 测试向量
//! - **NIST SP 800-38D Test Case 14** —— AES-256-GCM(我们用来 wrap 下层密钥)
//!
//! 一旦其中任一向量失败,要么底层 crate 升级改了行为(必须升级 vault 格式版本号),
//! 要么我们的算法配置(version / block size / KDF 参数)被错误改动。

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, AssociatedData, KeyId, Params, ParamsBuilder, Version};
use chacha20poly1305::aead::Payload;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crypto_core::random;

// ---------------------------------------------------------------------------
// RFC 9106 Appendix A.1 — Argon2id v1.3 official test vector.
//
//   Password:        32 bytes of 0x01
//   Salt:            16 bytes of 0x02
//   Secret:           8 bytes of 0x03
//   Associated data: 12 bytes of 0x04
//   Memory:          32 KiB
//   Iterations:      3
//   Parallelism:     4 lanes
//   Tag length:      32 bytes
//
// Expected tag(RFC 9106 §A.1 v1.3):
//   0d 64 0d f5 8d 78 76 6c 08 c0 37 a3 4a 8b 53 c9
//   d0 1e f0 45 2d 75 b6 5e b5 25 20 e9 6b 01 e6 59
// ---------------------------------------------------------------------------

const RFC9106_TAG_HEX: &str =
    "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659";

#[test]
fn argon2id_rfc9106_a1_test_vector() {
    // RFC 9106 §A.1
    let password = [0x01u8; 32];
    let salt = [0x02u8; 16];
    let secret = [0x03u8; 8];
    let ad = [0x04u8; 12];

    let mut params_builder = ParamsBuilder::new();
    params_builder
        .m_cost(32) // 32 KiB
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .data(AssociatedData::new(&ad).unwrap())
        .keyid(KeyId::new(&[]).unwrap());
    let params: Params = params_builder.build().unwrap();

    let argon =
        Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params).unwrap();

    let mut out = [0u8; 32];
    argon
        .hash_password_into(&password, &salt, &mut out)
        .unwrap();

    assert_eq!(
        hex::encode(out),
        RFC9106_TAG_HEX,
        "RFC 9106 Appendix A.1 Argon2id v1.3 向量失败 — \
         底层 argon2 crate 行为已变更,需排查"
    );
}

#[test]
fn argon2id_rfc9106_version_is_v1_3() {
    // 防回归:Version::V0x13 必须等于 0x13(RFC 9106 标准版本)。
    // 任何旧 Version(如 0x10)直接拒绝。
    assert_eq!(Version::V0x13 as u32, 0x13);
}

// ---------------------------------------------------------------------------
// draft-irtf-cfrg-xchacha-03 Appendix A.3.1 — XChaCha20-Poly1305 official vector.
//
//   Key:        0x80..0x9f (32 bytes)
//   Nonce:      0x40..0x57 (24 bytes)
//   AAD:        0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7
//   Plaintext:  "Ladies and Gentlemen of the class of '99: ..."(114 bytes)
//   Ciphertext: 114 bytes + 16 byte Poly1305 tag
// ---------------------------------------------------------------------------

const IRTF_XCHACHA_CIPHERTEXT_HEX: &str = concat!(
    "bd6d179d3e83d43b9576579493c0e939",
    "572a1700252bfaccbed2902c21396cbb",
    "731c7f1b0b4aa6440bf3a82f4eda7e39",
    "ae64c6708c54c216cb96b72e1213b452",
    "2f8c9ba40db5d945b11b69b982c1bb9e",
    "3f3fac2bc369488f76b2383565d3fff9",
    "21f9664c97637da9768812f615c68b13",
    "b52ec0875924c1c7987947deafd8780a",
    "cf49",
);

#[test]
fn xchacha20poly1305_irtf_a31_test_vector() {
    let key: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    let nonce: [u8; 24] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    ];
    let aad: [u8; 12] = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key));
    let n = XNonce::from_slice(&nonce);

    let ct = cipher
        .encrypt(
            n,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .unwrap();

    assert_eq!(
        hex::encode(&ct),
        IRTF_XCHACHA_CIPHERTEXT_HEX,
        "IRTF draft-irtf-cfrg-xchacha §A.3.1 向量失败 — \
         底层 chacha20poly1305 crate 行为已变更,需排查"
    );

    // 反向解密也必须成功且不被任何字段篡改通过。
    let pt = cipher
        .decrypt(
            n,
            Payload {
                msg: &ct,
                aad: &aad,
            },
        )
        .unwrap();
    assert_eq!(pt, plaintext);
}

// ---------------------------------------------------------------------------
// NIST SP 800-38D — AES-256-GCM Test Case 14.
//
// 我们用 AES-256-GCM 包装下层对称密钥(wrap_key / unwrap_key)。
// Test Case 14(All-zero key + All-zero plaintext):
//   Key:       32 bytes of 0
//   IV:        12 bytes of 0
//   Plaintext: 16 bytes of 0
//   AAD:       (empty)
//   Tag:       d0d1c8a799996bf0265b98b5d48ab919
//   Ciphertext: cea7403d4d606b6e074ec5d3baf39d18
// ---------------------------------------------------------------------------

#[test]
fn aes256_gcm_nist_test_case_14() {
    let key = [0u8; 32];
    let iv = [0u8; 12];
    let plaintext = [0u8; 16];

    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let nonce = Nonce::from_slice(&iv);

    let ct = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
    // ct = ciphertext (16) || tag (16)
    let ct_hex = hex::encode(&ct);
    assert_eq!(
        ct_hex,
        "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919",
        "NIST SP 800-38D AES-256-GCM Test Case 14 失败"
    );

    // 反向必须能解出全零明文。
    let recovered = cipher.decrypt(nonce, ct.as_ref()).unwrap();
    assert_eq!(recovered, plaintext);
}

// ---------------------------------------------------------------------------
// RNG 性质测试(crypto_core::random)。
//
// 严格意义上 CSPRNG 不可能"测出"密码学强度,但这些 sanity 测试能挡掉
// "实现错误地反复返回同样字节 / 没正确读到 OS 熵源 / 全零"这类问题。
// ---------------------------------------------------------------------------

#[test]
fn rng_two_draws_of_32_bytes_must_differ() {
    let a = random::bytes::<32>().unwrap();
    let b = random::bytes::<32>().unwrap();
    assert_ne!(a, b, "RNG 两次 32 字节抽样返回相同值 — 熵源失效");
}

#[test]
fn rng_never_returns_all_zero() {
    // 32B 全零的概率是 2^-256,实际看见即可断定 RNG 坏了。
    let a = random::bytes::<32>().unwrap();
    assert!(a.iter().any(|&b| b != 0), "RNG 返回全零 32B — 异常");
}

#[test]
fn rng_distribution_smoke_check_64_draws() {
    // 用 64 次 32 字节抽样组成 2048 字节,简单频次检查:
    // 任意单字节出现频率都不应严重偏差(防止 "一直返回 0x42" 这类 bug)。
    let mut bucket = [0u32; 256];
    for _ in 0..64 {
        let buf = random::bytes::<32>().unwrap();
        for &b in &buf {
            bucket[b as usize] += 1;
        }
    }
    // 期望 2048 / 256 = 8。允许 0..=64(超宽松,只挡严重偏差)。
    let max = *bucket.iter().max().unwrap();
    assert!(
        max <= 64,
        "RNG 输出严重偏向单一字节(max bucket = {max}/2048)"
    );
}

#[test]
fn rng_fill_writes_into_user_buffer() {
    // random::fill 写入 caller 的 buffer。
    let mut buf = [0u8; 16];
    random::fill(&mut buf).unwrap();
    assert!(buf.iter().any(|&b| b != 0));
}

#[test]
fn rng_zero_length_fill_is_noop() {
    // 0 字节抽样不应 panic / 不应失败。
    let mut buf: [u8; 0] = [];
    random::fill(&mut buf).unwrap();
    let _ = random::bytes::<0>().unwrap();
}

#[test]
fn rng_many_draws_have_no_duplicates() {
    // 128 个独立 32 字节抽样:不允许任意两个相等。
    let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for _ in 0..128 {
        let b = random::bytes::<32>().unwrap();
        assert!(seen.insert(b), "RNG 出现重复 32B 输出");
    }
}

/// crypto_core 顶级元数据可访问。
#[test]
fn crate_version_is_exposed() {
    let v = crypto_core::version();
    assert!(!v.is_empty());
    assert_eq!(v, env!("CARGO_PKG_VERSION"));
}
