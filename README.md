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
        │  AES-256-GCM-SIV
        ▼
    KEK  (Key Encryption Key)          ← 账户模型下由 ARK(账户根密钥)包裹
        │  AES-256-GCM-SIV
        ▼
    VMK  (Vault Master Key)
        │  AES-256-GCM-SIV
        ▼
    IKEK (Item KEK)
        │  AES-256-GCM-SIV(per item)
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
| 共享密封 | libsodium `crypto_box_seal`(经 dryoc 1.0,纯 Rust) | X25519 + XSalsa20-Poly1305 匿名密封盒;不自实现,直接用审计过的 libsodium 构造(含低阶点公钥拒绝) |
| 口令预处理 | NFKD 归一化 | 跨平台输入一致性 |

完整规约见 [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md)(红线、AAD 模板、错误处理、回归保护)。

## 为什么没有 1Password 那样的 Secret Key

1Password 的 Secret Key 是第二因子:密文托管在服务商那里,万一服务端数据库泄露,
攻击者拿到密文也因为缺 Secret Key 而无法离线爆破。它解决的是**「密文在别人手里」**的问题。

RootKey 不托管密文 —— 数据只在你的设备和你自己指定的同步位置。所以我们做了另一个取舍(ADR-001):
**单因子主密码 + 高成本 KDF**(Argon2id m=128 MiB / t=3 / p=4)+ **主密码门槛**(≥ 12 位且 zxcvbn ≥ 3)。

代价要说清楚:如果你把同步位置(WebDAV / 网盘)里的密文**和一个弱主密码同时**交了出去,
理论上可被离线爆破。Secret Key 挡的就是这一步;我们靠 KDF 成本和密码强度门槛挡。
两者不是等价的 —— 前者是数学上的不可分辨,后者是把成本抬到不划算。我们认为对
「密文不离开自己掌控」的模型,这个取舍成立;如果将来加入第二因子,会作为可选项,不替换主密码。

## 不读代码也能验证

[`docs/crypto-vectors.md`](docs/crypto-vectors.md) 提供了固定输入的测试向量 ——
用任何语言的标准 Argon2id / XChaCha20-Poly1305 实现都能独立复算,验证我们的
派生流程没有私货。这些向量同时被本仓测试(`tests/`)锁定,CI 里任何偏离都会红。

```bash
cargo test          # 168 个测试,含 KAT 向量与跨语言契约
```

### 验证「与产品逐字节同源」

产品每次发版都会公布该版本 `crypto_core/src` 的源码树哈希(下载页与发布说明里),
本仓对应版本打同名 tag。你可以自己算一遍对比:

```bash
git checkout v0.4.0
find src -type f | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256
```

> 目前验证的是**源码**同源。二进制级的可复现构建(从本仓编出与发行版逐字节相同的产物)
> 还在路线图上 —— Flutter + Rust FFI 的全链路确定性构建尚未完成,我们不假装已经做到。

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
