# rootkey-crypto

[RootKey(小密盾)](https://rootkey.bitbeam.cn) 密码管理器的**加密核心**,完整开源,欢迎审查。

> **English**: This is the complete cryptographic core of the RootKey password manager,
> published for public audit. Key derivation, key hierarchy, AEAD, signing and sealed
> sharing — everything that touches your secrets — is in this repo, byte-for-byte
> identical to what ships in the product. The UI and commercial layers stay closed;
> per Kerckhoffs's principle, none of the security depends on them being secret.

## 为什么开源这一层

密码管理器卖的是信任,而"请相信我加密做对了"无法口头证明。

- **加密系统的安全性只应依赖密钥,不依赖算法保密**(Kerckhoffs 原则)。公开这一层不减一分安全。
- 产品里所有接触明文与密钥的代码都在这个 crate 里 —— UI 只是它的调用方。审计了它,就审计了数据安全的全部命门。
- 本仓与商业产品**逐字节同源**:产品主仓以此为真源构建,发版时同步快照到这里(版本号一致)。

## 密钥层次

```text
Master Password(用户记忆,UI 强制 ≥ 12 位 + zxcvbn ≥ 3)
        │  Argon2id(salt 32B, m=128 MiB, t=3, p=4)
        ▼
    MUK  (Master Unlock Key)
        │  AES-256-GCM
        ▼
    KEK  (Key Encryption Key)          ← 账户模型下由 ARK(账户根密钥)包裹
        │  AES-256-GCM
        ▼
    VMK  (Vault Master Key)
        │  AES-256-GCM
        ▼
    IKEK (Item KEK)
        │  AES-256-GCM(per item)
        ▼
 ItemKey (per item)
        │  XChaCha20-Poly1305
        ▼
 Item Plaintext
```

主密码永不落盘、永不上传;所有中间密钥在内存中以 `Zeroizing` 持有,离开作用域即擦除。

## 算法与参数

| 用途 | 选型 | 参数 |
|---|---|---|
| 口令派生 | Argon2id | m=128 MiB(OWASP 2024 最低档 19 MiB 的 6.7 倍),t=3,p=4,salt 32B |
| 密钥包裹 | AES-256-GCM-SIV(RFC 8452) | 随机 96-bit nonce,AAD 绑定层级与格式版本;nonce-misuse-resistant,适合长命包裹密钥 |
| 条目加密 | XChaCha20-Poly1305 | 随机 192-bit nonce |
| 文件签名 | Ed25519 | vault manifest 防篡改/回滚 |
| 共享密封 | X25519 ECDH → BLAKE3 KDF → XChaCha20-Poly1305 | ECDH 输出经 BLAKE3::derive_key 派生密钥(非裸用)+ 校验 was_contributory 拒低阶点;nonce = BLAKE3(epk ‖ rcpt_pk)[..24] |
| 口令预处理 | NFKD 归一化 | 跨平台输入一致性 |

完整规约见 [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md)(红线、AAD 模板、错误处理、回归保护)。

## 不读代码也能验证

[`docs/crypto-vectors.md`](docs/crypto-vectors.md) 提供了固定输入的测试向量 ——
用任何语言的标准 Argon2id / XChaCha20-Poly1305 实现都能独立复算,验证我们的
派生流程没有私货。这些向量同时被本仓测试(`tests/`)锁定,CI 里任何偏离都会红。

```bash
cargo test          # 165 个测试,含 KAT 向量与跨语言契约
```

## 文档

- [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) — 密码学规约(与代码强契约)
- [`docs/VAULT_FORMAT.md`](docs/VAULT_FORMAT.md) — 落盘格式,第三方可实现读取器
- [`docs/threat-model.md`](docs/threat-model.md) — 信任边界与明确不覆盖的场景
- [`docs/crypto-vectors.md`](docs/crypto-vectors.md) — 可独立验证的测试向量

## 发现安全问题?

请**不要**提公开 issue,发邮件到 hi@bitbeam.cn(标题注明 SECURITY)。
确认的问题会在修复发布后公开致谢。详见 [SECURITY.md](SECURITY.md)。

## 许可

MIT OR Apache-2.0,任选其一。
