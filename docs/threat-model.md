# RootKey 威胁模型

> 状态:v1.0 / 2026-05-22
> 配套文档:[../SECURITY_MODEL.md](SECURITY_MODEL.md)(密码学规约)、[crypto-vectors.md](crypto-vectors.md)(可验证向量)

本文公开 RootKey 的信任边界、攻击者能力假设、明确不在保护范围内的场景。**目的**:让第三方在不读代码的前提下能判断"我的威胁能不能被这套设计覆盖"。

## 1. 信任边界(Trust Boundaries)

```
┌─────────────────────────────────────────────────────────────┐
│                  用户的物理设备 (Trusted)                    │
│                                                              │
│  ┌──────────────┐   IPC/socket   ┌──────────────────────┐   │
│  │ Flutter UI   │ ──── token ──> │ Rust 核心 (Trusted)  │   │
│  │ (Dart)       │                │  ┌─────────────────┐ │   │
│  │  - 路由       │                │  │ crypto_core     │ │   │
│  │  - 状态       │                │  │ vault manager   │ │   │
│  │  - 不持 key   │ <── handle ─── │  │ sync engine     │ │   │
│  └──────────────┘                │  │ watchtower      │ │   │
│         ↓                        │  │ FFI bridge      │ │   │
│   渲染:仅展示                    │  └─────────────────┘ │   │
│   操作:经 FFI                   │  内存:Zeroize        │   │
│                                  │  密文:文件系统       │   │
│                                  └──────────────────────┘   │
│                                              ↓               │
│                                  ┌──────────────────────┐   │
│                                  │ 系统 Keychain        │   │
│                                  │ (Trusted-but-bounded)│   │
│                                  │ 缓存 wrapper key,    │   │
│                                  │ 失败 N 次清空        │   │
│                                  └──────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                          ↓ ciphertext only
                ┌──────────────────────────────┐
                │ 同步通道 (Untrusted)         │
                │ WebDAV / 本地文件夹           │
                │ 攻击者假设可读 / 可写 / 可篡改 │
                └──────────────────────────────┘
```

Rust 核心中,只有 `crypto_core` 在本仓公开;vault manager / sync engine / watchtower / FFI bridge 属产品闭源层,均只是 `crypto_core` 的调用方,不各自实现密码学。

**Trusted 区(我们必须保护)**:Rust 进程内存、crypto_core 的密钥与中间缓冲、vault 文件落盘前的明文。

**Trusted-but-bounded(部分保护)**:系统 Keychain / Secure Enclave。**信任 OS** 把 wrapper key 隔离,但承认越狱 / Root 设备可能突破;突破后 fallback 到仅主密码模型。

**Untrusted 区(假设可被攻击者完全控制)**:同步通道、运营商网络、云端文件系统、备份服务。这些只见密文,无任何元数据(item 数量除外:文件个数可见,但不暴露 item 类型 / 名称)。

## 2. 攻击者能力分级

| 等级 | 能力 | 我们必须防 |
|---|---|---|
| **A1 网络被动监听** | 抓 WebDAV / TCP 流量 | 是(全密文 + TLS) |
| **A2 网络主动篡改** | MitM,改 sync 包 | 是(端到端加密 + manifest hash + rev 防回滚) |
| **A3 云存储入侵** | 拿到 WebDAV / S3 bucket 全部文件 | 是(密文 + Argon2id 128 MiB,需爆破主密码) |
| **A4 本地物理访问(已锁)** | 拿到锁屏状态的笔记本 | 是(主密码 / 生物识别 N 次失败清缓存) |
| **A5 本地物理访问(解锁中)** | 拿到解锁状态的设备 | **部分**:自动锁 + 息屏即锁;若 60s 内用户离开未息屏,vault 可见 |
| **A6 进程内存 dump** | root / 调试器 dump Rust 进程 | **部分**:Zeroize 解锁中存在,锁后清;dump 在解锁瞬间能拿 key,但锁后无残留 |
| **A7 同设备其他 app(沙盒外)** | Mac 上同用户运行的恶意 app | **部分**:CLI socket 走 per-session token 防接管;但 OS 级 keylogger / 屏幕录制不在防护范围(系统隔离责任) |
| **A8 浏览器扩展供应链污染** | 攻击者控制扩展更新通道 | **部分**:扩展拿到的 credential 由用户在 RootKey UI 二次确认,但 passkey 流程的 origin 校验是唯一防线 |
| **A9 越狱 / Root 设备** | iOS 越狱、macOS SIP 关 | **fallback**:Keychain wrapper key 被读时,降级为"每次解锁都输主密码" |
| **A10 拥有完整 vault 文件的离线攻击者** | 拿到 ciphertext + keyset.json | 仅靠 Argon2id m=128 MiB + 主密码熵防爆破。**强主密码是唯一防线** |

## 3. 明确不在保护范围(Out of Scope)

以下场景**设计上不保护**,主动声明而不是"暗暗失败":

1. **主密码本身被键盘记录器 / 屏幕录制窃取** — OS 级威胁,不可由应用层防御
2. **用户在不可信设备上输入主密码** — 公用电脑 / 远程桌面 → 攻击者直接拿到主密码
3. **用户主动截屏 / 录制 vault 显示画面** — 已解锁内容用户自己负责
4. **主密码遗忘后的数据恢复** — ADR-001 明确没有恢复路径
5. **同一同步通道下 N 台设备的相互窃听** — 所有持有主密码的设备都拥有完整 vault 访问权;吊销特定设备需要主密码改 + 主动同步
6. **同步服务商对 vault 文件的"存在性删除"** — 攻击者删了 vault 文件,我们只能告诉用户"远端没了",不能恢复;依赖用户自己保留本地副本
7. **针对 Rust 依赖的 0day** — 通过 cargo-audit / cargo-deny / pin 版本缓解,但不能保证;依赖第三方 crate 漏洞披露时效
8. **量子计算机破解 AES / ChaCha20** — 后量子算法在路线图,但当前不抵御 CRQC

## 4. 元数据泄露(Metadata Leakage)

同步到 WebDAV 的文件会泄露:

| 元数据 | 是否泄露 | 缓解 |
|---|---|---|
| Item 个数 | **泄露**(每个 item 一个文件) | 接受 — 隐藏个数需 padding 重传整 manifest,流量代价高 |
| 单个 item 大小 | **泄露**(密文长度) | 接受 — 长度泄露不暴露内容类型(加密+ AEAD tag,login / note 长度相似) |
| 文件 mtime | **泄露**(WebDAV 自然属性) | 接受 — 同步频率本身不是秘密 |
| 同步频率 | **泄露**(网络观察) | 接受 |
| Item 名称 / URL | **不泄露** | 都在 ciphertext 内 |
| Tags / favorite / archive 状态 | **不泄露** | 在 encrypted manifest 内 |
| Vault 总大小 | **泄露**(目录尺寸) | 接受 |

## 5. 已知不变量(Invariants)

代码 + 文档共守的硬约束:

- **N1**:Argon2id 参数低于 OWASP 2024 基线(m=19 MiB / t=2 / p=1)的 vault 必须解锁失败
- **N2**:同一密钥 + 同一 nonce 加密两次,不允许出现(随机 nonce + 失败立即 abort)
- **N3**:主密码 NFKD 归一化前后必须派生同一 MUK
- **N4**:vault 文件在落盘前,所有 plaintext 字段必须经 XChaCha20-Poly1305 加密
- **N5**:FFI 边界返回给 Dart 的对象不允许包含原始密钥字节(只允许密文 / handle / 摘要)
- **N6**:主密码错误与密文被篡改在错误码上不可区分
- **N7**:每次 unlock 失败都不削弱后续 unlock 的成功率(无登录锁定,但生物识别 N 次失败清 Keychain 缓存)
- **N8**:CLI / Browser Extension 调用必须通过 per-session token + origin 校验,不能裸调内核 FFI
- **N9**:Passkey 流程的 UV(User Verification)flag 必须据实置位,不允许对 RP 谎报

N1-N7 由本仓测试与产品主仓的 vault / 同步 / FFI 集成测试覆盖。N8 由 CLI / 扩展层测试覆盖。N9 由 Passkey 层测试覆盖。

## 6. 已知局限与路线

| 局限 | 状态 | 计划 |
|---|---|---|
| 无第三方审计 | 已知 | Phase 3 资助 Cure53 / Trail of Bits |
| 无 reproducible build | 已知 | tools/ 增 cargo-bisect 配置,持续 |
| 无 Ed25519 vault 签名 | 已知 | Phase 2 |
| 无 IKEK 自动旋转 | 已知 | Phase 2 |
| 无后量子算法 | 已知 | 等 NIST 定型 + 主流库稳定 |
| 同设备多用户隔离弱 | 已知 | 依赖 OS 用户分离;不做应用级 |

## 7. 报告漏洞

发现安全问题:邮件 `security@bitbeam.cn`(或仓库 SECURITY.md 列出的联系方式)。**请不要在公开 issue 上披露未修复的漏洞**。我们会在 7 天内回复确认收到,30 天内出修复或给出迁移路径。
