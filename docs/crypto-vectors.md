# RootKey 密码学测试向量

> 状态:v1.0 / 2026-05-22
> 配套文档:[../SECURITY_MODEL.md](SECURITY_MODEL.md)、[threat-model.md](threat-model.md)

本文公开 RootKey 的可验证测试向量。**目的**:不读 Rust 代码也能用任何 Argon2id / XChaCha20-Poly1305 实现独立验证我们的派生流程是标准的。

## 1. Argon2id 派生 MUK(项目契约向量)

这是项目特有的契约 — 锁定主密码 / salt / 参数 → 一定派生出锁定的 MUK。任何依赖升级、归一化方式变更、内部布局变更若导致输出变化,**必须升级 vault 格式版本号并提供迁移路径**(代码:`src/lib.rs::KEYSET_FORMAT_VERSION`)。

### 输入

| 参数 | 值 |
|---|---|
| Password (UTF-8) | `correct horse battery staple` |
| Password NFKD | 等于 UTF-8(纯 ASCII,归一化不变) |
| Salt (32 bytes, hex) | `0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20` |
| Algorithm | Argon2id (RFC 9106) |
| Argon2 version | 0x13(19,十进制) |
| Memory | 19 MiB(19 × 1024 KiB)= 19456 |
| Iterations (t) | 2 |
| Parallelism (p) | 1 |
| Output length | 32 bytes |
| Secret (K) | (无,ADR-001 后无 Secret Key) |

### 期望输出

```
MUK (32 bytes, hex):
daae46b9501cf909ede5ce3241fa4d0509a9b2e1fb0fc31198f5fdc0a82620b1
```

### 独立验证

任何符合 RFC 9106 的 Argon2id 实现应能复现该值。Python 参考:

```python
from argon2.low_level import hash_secret_raw, Type

password = b"correct horse battery staple"
salt = bytes.fromhex("0102030405060708090a0b0c0d0e0f10"
                     "1112131415161718191a1b1c1d1e1f20")

muk = hash_secret_raw(
    secret=password,
    salt=salt,
    time_cost=2,
    memory_cost=19 * 1024,  # KiB
    parallelism=1,
    hash_len=32,
    type=Type.ID,
    version=0x13,
)
assert muk.hex() == "daae46b9501cf909ede5ce3241fa4d0509a9b2e1fb0fc31198f5fdc0a82620b1"
```

测试位置:`tests/test_vectors.rs::derive_muk_fixed_input_locked_hex`
期望值文件:`tests/vectors/derive_muk_fixed.hex`

## 2. XChaCha20-Poly1305 round-trip(标准向量)

验证我们的 AEAD 用法符合 IETF draft `draft-irtf-cfrg-xchacha`。**这不是项目契约 —** 测试 RustCrypto crate 行为是否标准。

### 输入

| 参数 | 值 |
|---|---|
| Key (32 bytes, hex) | `808182838485868788898a8b8c8d8e8f` `909192939495969798999a9b9c9d9e9f` |
| Nonce (24 bytes, hex) | `404142434445464748494a4b4c4d4e4f` `5051525354555657` |
| AAD (12 bytes, hex) | `50515253c0c1c2c3c4c5c6c7` |
| Plaintext (UTF-8) | `Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.` |

### 期望输出

- 密文长度 = plaintext.len() + 16(AEAD tag)
- 用相同 key / nonce / aad 解密返回原 plaintext
- AAD 任意位翻转 → 解密失败

测试位置:`tests/test_vectors.rs::xchacha20poly1305_round_trip_with_known_inputs`

## 3. NFKD 归一化等价性

视觉等价的不同 Unicode 表达,经 NFKD 归一化后派生**同一**MUK。

### 输入

| 形式 | 字节序列(UTF-8 hex) |
|---|---|
| NFC | `ma\u{00F1}ana` → `6d61c3b1616e61` |
| NFD | `man\u{0303}ana` → `6d616ecc83616e61` |

两者均使用项目契约向量的 salt + 参数派生 MUK,期望输出**相同**。

测试位置:`src/kdf.rs::tests::nfkd_normalization_treats_visually_equal_passwords_as_equal`

## 4. 端到端 round-trip(无固定向量,但有断言)

`create_vault_keys("p@ssw0rd!") → encrypt_item(b"hello world", &unlocked) → unlock_vault("p@ssw0rd!", &encrypted) → decrypt_item` 必须返回原 plaintext。错误密码必须返回 `DecryptFailed`,与"密文被篡改"在错误码上不可区分。

测试位置:`tests/test_vectors.rs::end_to_end_with_fixed_password`

## 5. 防降级:KDF 参数低于 OWASP 基线必被拒

| 参数 | 值 | 期望 |
|---|---|---|
| memory_kib | 18 × 1024(低于 OWASP 2024 最低 19 MiB) | `InvalidArgument` |
| memory_kib | 19 × 1024,time_cost=2,parallelism=1 | 通过(OWASP 2024 最低档) |
| memory_kib | 128 × 1024,time_cost=3,parallelism=4 | 通过(项目默认) |
| salt | 全零 32 字节 | `InvalidArgument` |
| algorithm | `scrypt` 等未知值 | 反序列化失败 |
| salt | 31 字节(短一字节) | 反序列化失败 |

测试位置:`src/kdf.rs::tests`(`rejects_params_below_minimum`、`owasp_baseline_accepted_one_below_rejected`、`rejects_all_zero_salt`、`kdf_params_rejects_wrong_salt_length_on_deserialize`、`kdf_params_rejects_unknown_algorithm`)

## 6. 防降级:KDF 参数纳入 AAD

`KdfParams::aad_bytes` 序列化为 1 + 4 + 4 + 4 + 32 = 45 字节,格式:

| Offset | 字节数 | 含义 |
|---|---|---|
| 0 | 1 | 算法标识(0x01 = Argon2id) |
| 1 | 4 | memory_kib,big-endian u32 |
| 5 | 4 | time_cost,big-endian u32 |
| 9 | 4 | parallelism,big-endian u32 |
| 13 | 32 | salt |

修改任一字段 → AAD 改变 → MUK 用旧 AAD 包装的 KEK 用新 AAD 解包失败。

测试位置:`src/kdf.rs::tests::aad_bytes_includes_all_fields`

## 7. 如何运行所有测试

```bash
cd crates/crypto_core
cargo test --release  # 含 derive_muk 固定向量(release 模式快)
```

成功输出包含:

```
test derive_muk_fixed_input_locked_hex ... ok
test derive_muk_fixed_input_is_deterministic ... ok
test xchacha20poly1305_round_trip_with_known_inputs ... ok
test end_to_end_with_fixed_password ... ok
test argon2id_basic_is_stable ... ok
```

测试失败若不是依赖升级造成,**禁止修改测试让其通过** — 这是与历史 vault 的契约,违反会让所有现存 vault 失效。
