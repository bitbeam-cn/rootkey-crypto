# 安全模型

> 状态:v0.4 / 2026-07-22 — 与 ADR-001(单主密码)+ ADR-010(一账户多逻辑 vault + 账户根密钥 ARK + 恢复密钥)及 crypto_core 当前实现同步

本文是 RootKey 的密码学规约。涵盖:不可妥协的红线、密钥层次、算法选型、AAD 模板、错误处理与回归保护。**与代码的契约**:任何一条改动都必须同步代码、升级 vault 格式版本、提供迁移路径。

详细威胁模型见 [docs/security/threat-model.md](threat-model.md);可验证的测试向量见 [docs/security/crypto-vectors.md](crypto-vectors.md)。

## 1. 不可妥协的红线

1. **Zero Knowledge** 云端永远只存密文
2. **主密码不存任何地方** 不存主密码或其等价物;忘记主密码可凭**恢复密钥**(离线、只在用户手上)重设 —— 恢复密钥同样不由服务器保管(ADR-010)
3. **Dart 不持 raw key** 明文密钥仅存在于 Rust 的 `Zeroize` / `Zeroizing<T>` 容器
4. **生物识别 / 恢复密钥各自本机包装 ARK**,都不替代主密码,也不上传
5. **AAD 必须包含上下文** account_id / vault_id / 层级标签 / KDF 参数
6. **AEAD nonce 永不复用** 每次加密重新从 OS CSPRNG 取
7. **KDF 参数纳入 AAD** 防降级攻击
8. **客户端硬编码 KDF 最低值** vault header 写更低的也拒绝
9. **同步先写本地** 网络错误不能丢数据
10. **不发明算法** 只组合标准原语;算法 / 派生流程变更必须升级 vault 格式版本

## 2. 密钥层次

```
Master Password
      │  NFKD 归一化 → Argon2id(salt 32B,m=128 MiB / t=3 / p=4 默认)
      ▼
  MUK   Master Unlock Key  (32B,账户级,全账户一份 salt)
      │  AES-256-GCM-SIV(AAD = root-key/wrap-ark/v1 + account_id + kdf_params)
      ▼
  ARK   Account Root Key  (32B,账户根密钥,ADR-010)
      │  AES-256-GCM-SIV(AAD = root-key/wrap-vault-kek/v1 + account_id + vault_id)
      ▼   ├─ 账户下每个逻辑 vault 一条:ARK 包装该 vault 的 KEK
  KEK   Key Encryption Key  (32B,per vault)
      │  AES-256-GCM-SIV(AAD = label + account_id + vault_id)
      ▼
  VMK   Vault Master Key  (32B,可旋转)
      │  AES-256-GCM-SIV(AAD = label + vault_id)
      ▼
  IKEK  Item Key Encryption Key  (32B,旋转 VMK 时只重新包装,本身不变)
      │  AES-256-GCM-SIV,per item(AAD = label + vault_id)
      ▼
 ItemKey 32B,per item
      │  XChaCha20-Poly1305(AAD = label + vault_id)
      ▼
 Item Plaintext
```

**ARK 的旁路包装(一次解锁开全部 vault + 找回路径)**:

| 包装者 | 存储 | 用途 |
|--------|------|------|
| MUK(主密码派生) | `account.json` `wrapped_ark` | 正常解锁 |
| 恢复密钥(RK-XXXXX-…,125-bit,blake3 derive_key 绑 account_id) | `account.json` `wrapped_ark_recovery`(可选) | 忘记主密码 → 重设(数据全留) |
| wrapper_key(OS Keychain,生物识别保护) | `account.biometric.json` | Touch ID / Face ID 快速解锁 |

恢复密钥本体**只显示一次**、打印进应急套件,系统不存明文;三条路径都只解开 ARK,ARK 以下(KEK/VMK/IKEK/item)不变。改主密码 / 换恢复密钥 / 换生物识别都是 O(1) 重包 ARK 一条,与 vault 数量无关。

引入 ARK + KEK / VMK / IKEK 中间密钥的好处:

| 操作 | 影响范围 |
|------|---------|
| 改主密码 | 只重新包装 KEK,VMK / IKEK / item 全部不动 |
| 旋转 VMK | 重新包装 IKEK,item 不动(IKEK 本身密钥不变) |
| Phase 2 旋转 IKEK(待加) | 需重新包装所有 item key,但 ItemKey / item ciphertext 仍可不动 |

## 3. 算法选型与默认参数

| 用途 | 算法 | 参数 |
|------|------|------|
| KDF | Argon2id(RFC 9106) | **m=128 MiB,t=3,p=4**,output=32B,salt=32B 随机 |
| 主密码归一化 | UTF-8 NFKD | 防止视觉等价 codepoint 派生不同 MUK |
| 包装 AEAD | AES-256-GCM-SIV(RFC 8452) | nonce=12B 随机;nonce-misuse-resistant,包裹密钥长命无轮换即便 nonce 偶发复用也只泄露"明文是否相等" |
| Item AEAD | XChaCha20-Poly1305 | nonce=24B 随机,碰撞概率可忽略 |
| 随机数 | OS CSPRNG via `getrandom` | 任何失败立即返回 `RngFailed` |
| 哈希 | BLAKE3 | 通用摘要 |
| 常数时间比较 | `subtle::ConstantTimeEq` | 校验和判定 |
| 内存清零 | `zeroize::ZeroizeOnDrop` + `Zeroizing<T>` | 所有密钥与中间缓冲 |
| 签名(Phase 2) | Ed25519 | vault 文件防篡改 |
| Sync rev 防回滚 | BLAKE3 over manifest + 单调 rev | 产品同步层已实现 |

**KDF 客户端最低值**(写入代码,vault header 即使指定更低也拒绝):

| 项 | 最低 | 来源 |
|----|------|------|
| memory | **19 MiB** | OWASP Password Storage Cheat Sheet 2024(Argon2id 最低档) |
| time | **2** | 同上 |
| parallelism | **1** | 同上 |

低于该组合的 vault 直接拒绝解锁。代码:`crypto_core::kdf::{MIN_MEMORY_KIB, MIN_TIME_COST, MIN_PARALLELISM}`。

## 4. AAD 模板

每层 AEAD 的 AAD 拼接规则,变更需升级 `KEYSET_FORMAT_VERSION`:

| 层 | AAD |
|----|-----|
| Wrapped KEK | `"root-key" + "/wrap-kek/v1/" + account_id + vault_id + kdf_params_canonical` |
| Wrapped VMK | `"root-key" + "/wrap-vmk/v1/" + account_id + vault_id` |
| Wrapped IKEK | `"root-key" + "/wrap-ikek/v1/" + vault_id` |
| Wrapped Item Key | `"root-key" + "/wrap-item-key/v1/" + vault_id` |
| Item Blob | `"root-key" + "/item-blob/v1/" + vault_id` |

KDF 参数序列化(`KdfParams::aad_bytes`):算法标识(1B) || memory_kib(BE u32) || time_cost(BE u32) || parallelism(BE u32) || salt(32B)。

## 5. 忘记主密码 = 凭恢复密钥重设(主密码与恢复密钥同时丢失才丢数据)

ADR-010 后有**恢复密钥**这条正规找回路径,但仍**无 Secret Key、无 Emergency Access、服务器不留任何凭据**:

- 服务器(若用同步)只见密文;主密码与恢复密钥都不上传、不留副本。
- 忘记主密码:解锁页「忘记主密码?」→ 输入恢复密钥(RK-XXXXX-…)→ 解开 ARK → 设新主密码,数据原样保留。
- 恢复密钥只在创建时显示一次并打印进应急套件(可打印凭据单,文件不含明文秘密);系统只存它包装 ARK 的密文。
- **主密码与恢复密钥同时丢失** = ARK 无法解开 = vault 永久打不开(这才是 Zero-Knowledge 的真正代价)。次级保险是「加密恢复备份(.rkvault,另设密码)」。

UI 强制主密码 ≥ 12 位 + zxcvbn score ≥ 3,创建流程生成恢复密钥并引导打印应急套件。

> 已知边界:主密码 / 恢复密钥字符串在 Dart 堆中不提供清零保证(明文密钥不出 Rust);ARK 目前无旋转函数(ARK 泄露则改密码/改恢复密钥都救不回),规划为「安全设置」低频入口。

## 6. 错误处理纪律

- 错误信息**不**告诉调用者"密码错"还是"数据被篡改",一律 `DecryptFailed`
- 错误**不**携带密钥 / 密码 / 明文 item 内容
- KDF 参数低于客户端最低值 → `InvalidArgument`,不区分具体哪个参数

## 7. 威胁模型摘要

完整 trust boundary + attacker capabilities + out-of-scope 见 [security/threat-model.md](threat-model.md)。摘要:

| # | 威胁 | 缓解 | 阶段 |
|---|------|------|------|
| T1 | 云端泄露密文 | 端到端加密 + Argon2id m=128 MiB | MVP |
| T2 | 主密码弱口令 | UI 强制 ≥ 12 位 + zxcvbn score ≥ 3 + memory hardness | MVP |
| T3 | 设备失窃已锁 | 包装密钥需主密码 / 生物识别才能解;失败 N 次清空缓存 | MVP |
| T4 | 设备失窃解锁中 | 自动锁定 + 息屏即锁 | MVP |
| T5 | 内存 dump | Zeroize / Zeroizing,锁定立即清,Dart 跨 FFI 不持 raw key | MVP |
| T6 | 剪贴板嗅探 | 30s 自动清 | MVP |
| T7 | FFI 边界泄漏 | Dart 拿到的只有密文 + 不透明 handle | MVP |
| T8 | 同步中间人 | TLS + 端到端加密(WebDAV / 本地文件) | MVP |
| T9 | 篡改同步包 | 单调 rev + 完整性校验(manifest hash) | MVP |
| T10 | 同步冲突丢数据 | 后写优先 + 手动冲突 UI | MVP |
| T11 | 弱随机数 | 强制 OS CSPRNG,任何失败 → `RngFailed` 中止 | MVP |
| T12 | KDF 参数降级 | 参数纳入 AAD + 客户端最低值校验(OWASP 2024 基线) | MVP |
| T13 | 时序侧信道 | 常数时间比较;失败原因不分类 | MVP |
| T14 | 备份链路 | 包装密钥被系统加密;密文本身无密钥不可解 | MVP |
| T15 | 浏览器扩展 XSS | Native Messaging,严格 origin 校验 | M1+ |
| T16 | 自动填充钓鱼 | 严格 etld+1 匹配 | M1+ |
| T17 | 供应链 | cargo-audit + cargo-deny + reproducible build(规划) | 持续 |
| T18 | 越狱 / Root 设备 | 启动时检测,降级为仅主密码(规划) | Phase 2 |
| T19 | 主密码遗忘 | 设计上不可恢复,UI 多次教育 | MVP |
| T20 | 协议自身缺陷 | 公开协议文档 + 第三方审计(Phase 3 规划) | 持续 |
| T21 | CLI 误用本地 socket | per-session token + caller-auth(Phase 2 已实装) | MVP |
| T22 | Passkey RP 假声明 UV | UV flag 据实置位,未做用户验证不对 RP 谎报 | MVP |
| T23 | AI(MCP)越权读写核心账号 | 免弹框但**死锁 ai-readable 白名单**;伪造 `id:"mcp"` 也只能在白名单内动手,范围守护端强制 | MVP |

## 8. 本地调用方门禁(CLI 与 MCP)

本机的 native socket(`<data_dir>/root-key/default/native.sock`,0600)对外暴露读写能力,
两类第一方调用方走**两套不同的门禁**。设计核心:**免确认 ⊕ 全范围,二者不可兼得**。

| 维度 | CLI(`rootkey …`,用户终端) | MCP(AI,请求 `id:"mcp"`) |
|---|---|---|
| `cli.token`(0600,256-bit,每 session 现铸) | 必须 | 必须 |
| App 运行 + 已解锁 | 必须 | 必须 |
| **每次写操作桌面弹框确认** | ✅ create/edit/delete 都弹 | ❌ 不弹 |
| **可操作范围** | 全部条目 | **只限 `ai-readable` 标签**(读/改/删/建都强制) |

- **信任边界**:socket + `cli.token` 均 0600 = **同一用户 + App 已解锁**即视为可信。这跟 App 自身的边界一致——同用户进程本就能读已解锁 App 的内存,`cli.token` 对同用户威胁不提供额外防线。CLI 能调用是设计内的(对标 1Password `op`),不是漏洞。
- **CLI 的弹框是额外防线**:针对「机器上某后台进程在我没看见时静默写库」这一担忧。**不要移除 CLI 侧确认**——CLI 不限范围,去掉确认 = 任何同用户进程可在解锁期静默改写整库。
- **MCP 免确认的前提不是「信任 AI」,而是范围锁**:AI 被死锁在 `ai-readable` 白名单内,blast radius 收窄到用户显式授权的条目;银行 / 主邮箱等未打标签的条目 AI 看不到也动不了。**这个范围锁替代了弹框**,是等价的安全闸,不是弱化。
- **enforce 点在守护端,不信客户端**:`is_mcp = env.id == "mcp"`;写路径 `if is_mcp && !payload_ai_readable(...) → 拒绝`,读路径 MCP client 侧再按 `ai-readable` 过滤。即使有人伪造 `id:"mcp"` 跳过弹框,也只能在白名单范围内动手——伪造的收益仅是「放弃全范围换免确认」,无净增权限。
- **AI 不能自我授权**:`ai-readable` 标签只能在 RootKey 界面里手动拨,MCP 无法给条目加/去此标签。

enforce 代码在产品的 FFI 守护层与 CLI 层(闭源部分),不在本仓范围内;本节列出规则是为了让审计者了解密钥之外的访问控制全貌。

## 9. 测试与回归保护

`crypto_core` 内 60+ 单元 + 集成测试。可验证的标准向量与项目内固定向量见 [security/crypto-vectors.md](crypto-vectors.md)。关键回归项:

- 主密码错误返回 `DecryptFailed`,与"密文被篡改"无法从错误码区分
- 同明文两次加密密文不同(nonce 随机)
- 篡改任一字段(密文 / nonce / wrapped key / KDF 参数)→ 解密失败
- 序列化结果(JSON)不包含任何密钥 / 明文 item 子串
- `Debug` 输出不泄字节
- NFKD 归一化:`"ma\u{00F1}ana"` 与 `"man\u{0303}ana"` 派生同一 MUK
- 改密码 / 旋转 VMK 后历史 item 仍可解
- **`derive_muk` 固定向量**:`correct horse battery staple` + salt=01..20 + (m=19 MiB / t=2 / p=1) → `daae46b9...82620b1`(完整 hex 见 vectors 文档)

任何修改导致固定向量失败,必须同时升级 `KEYSET_FORMAT_VERSION` 并提供迁移路径。
