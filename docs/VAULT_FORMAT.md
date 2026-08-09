# Vault 格式

> 状态:草案 v0.4 / 2026-07-21 — ADR-010 账户模型:密钥上移账户层,vault 目录只剩 keyslot

## 1. 目录布局

```
<data_root>/                          # <data_dir>/root-key/
├── account.json                     # 账户级 keyset:KDF + wrapped ARK + per-vault wrapped KEK
├── account.biometric.json           # 账户级生物识别信封(可选)
└── <vault_dir>/
```

```
<vault_dir>/
├── vault.json                       # 明文:vault 元数据(无密钥)
├── keyslot.json                     # 本 vault 密钥残余:wrapped VMK / wrapped IKEK
├── manifest.enc                     # 加密:ManifestPayload(item 索引)
├── items/
│   └── {item_id}.item               # 单条 item 文件(明文头 + 加密 blob)
├── trash/
│   └── {item_id}.item               # 软删除项,与 items/ 同结构
├── history/
│   └── {item_id}/
│       └── {version}.item           # 历史版本快照
└── attachments/
    └── {attachment_id}.blob         # 附件密文(Phase 2 实装)
```

设计原则:
1. **文件粒度即同步粒度**,每条 item 独立文件 → 同步层做差量、冲突合并、版本归档都简单
2. **manifest 是索引缓存**,可由 [`VaultManager::rebuild_manifest`] 从 `items/` + `trash/` 重建
3. **写入采用原子重命名**(`.tmp` → `rename`),崩溃恢复后不留半截文件

## 2. 文件格式

### 2.1 `vault.json`(明文)

```jsonc
{
  "schema_version": 2,
  "vault_id": "<UUID>",
  "created_at": 1714137600000,
  "updated_at": 1714137600000,
  "display_name": "Personal"           // 可选
}
```

密钥不在 vault.json:账户级链(MUK → ARK → per-vault KEK)在 `<data_root>/account.json`,
KEK 以下(wrapped VMK / IKEK)在本目录 `keyslot.json`(`crypto_core::VaultKeySlot`)。
密钥层次详见 [SECURITY_MODEL.md](SECURITY_MODEL.md) 与 ADR-010。

### 2.2 `manifest.enc`(加密)

文件本身是 [`crypto_core::EncryptedItemBlob`] 的 JSON 序列化,与 `items/` 下的 item 同样的加密管线
(随机 ItemKey + IKEK 包装 + XChaCha20-Poly1305 加密 payload)。解密后是 [`ManifestPayload`]:

```jsonc
{
  "schema_version": 1,
  "vault_id": "<UUID>",
  "items": [
    {
      "id": "<UUID>",
      "item_type": "login",
      "title": "GitHub",
      "subtitle": "alice",
      "favorite": true,
      "tags": ["work", "open-source"],
      "version": 3,
      "updated_at": 1714137600000,
      "last_used_at": 1714138000000,
      "archived_at": null,
      "deleted_at": null
    },
    ...
  ],
  "updated_at": 1714137600000
}
```

manifest 的作用:
- **快速列表 / 搜索**:UI 列表只读 manifest,无需打开每个 item 文件
- **同步元数据**:同步层比对 `version` / `updated_at` 决定是否拉取
- **可重建**:[`VaultManager::rebuild_manifest`] 扫 `items/` + `trash/` 重新解密生成

### 2.3 `items/{item_id}.item`(混合)

JSON 文件,顶层是明文 [`ItemRecord`] 元数据,只有 `encrypted_blob` 字段是密文。

```jsonc
{
  "schema_version": 1,
  "id": "<UUID>",
  "vault_id": "<UUID>",
  "version": 3,
  "created_at": 1700000000000,
  "updated_at": 1714137600000,
  "last_used_at": 1714138000000,
  "archived_at": null,
  "deleted_at": null,
  "encrypted_blob": {
    "version": 1,
    "wrapped_item_key": { "nonce": "<12B>", "ciphertext": "<48B>" },
    "blob":             { "nonce": "<24B>", "ciphertext": "<N+16B>" }
  }
}
```

明文头只暴露同步要用的最小集(id / version / 时间戳),其余字段全在 `encrypted_blob` 里。

### 2.4 `encrypted_blob` 解密后(`ItemPayload`)

```jsonc
{
  "title": "GitHub",
  "subtitle": "alice",
  "favorite": true,
  "tags": ["work"],
  "security_flags": {
    "require_reauth": false,
    "block_clipboard": false,
    "disable_autofill": false,
    "local_only": false
  },
  "body": {
    "type": "login",                  // tagged union
    "username": "alice",
    "password": "...",
    "urls": [
      { "url": "https://github.com", "match_mode": "base_domain" }
    ],
    "totp": "otpauth://totp/...",
    "notes": "..."
  },
  "custom_fields": [
    {
      "id": "<UUID>",
      "label": "Recovery key",
      "field_type": "concealed",
      "value": "...",
      "order": 0
    }
  ],
  "attachments": [
    {
      "id": "<UUID>",
      "filename": "id_card.png",
      "mime_type": "image/png",
      "size_bytes": 24576,
      "created_at": 1714137600000
    }
  ]
}
```

### 2.5 `trash/{item_id}.item`

与 `items/` 完全同构。区别在于 `deleted_at` 一定不为空,且文件物理位置在 `trash/` 下。
[`VaultManager::restore_item`] 把文件移回 `items/` 并清掉 `deleted_at`。

### 2.6 `history/{item_id}/{version}.item`

与 `items/` 完全同构,但内容是历史版本(更新前的快照)。MVP 默认每条 item 保留最近
[`DEFAULT_HISTORY_RETENTION`](=10) 个版本,超出后从最早开始物理删。

### 2.7 `attachments/{attachment_id}.blob`(Phase 2)

Phase 1 只在 [`AttachmentRef`] 里占位元数据,实际字节文件 / 加密管线 / 分块在 Phase 2 实装。
预期格式:整文件 XChaCha20-Poly1305,大文件按 1 MiB 分块,每块独立 nonce + tag。

## 3. Item 类型矩阵

### 3.1 MVP(10 类)

| Type tag | Body 必填字段 | 用途 |
|----------|---------------|------|
| `login` | — | 网站 / App 登录(用户名 / 密码 / URL / TOTP) |
| `password` | `password` | 单纯密码(无用户名概念) |
| `secure_note` | `content` | 多行安全备注 |
| `credit_card` | `number` | 信用卡 |
| `identity` | — | 身份信息 |
| `wifi` | `ssid` | WiFi |
| `api_token` | `token` | API Token |
| `database` | `host` | 数据库连接 |
| `server` | `host` | 服务器(SSH / RDP) |
| `software_license` | `product`, `license_key` | 软件许可 |

### 3.2 Phase 2(7 类,占位)

| Type tag | Body 必填字段 |
|----------|---------------|
| `bank_account` | `bank` |
| `passport` | `number` |
| `driver_license` | `number` |
| `email_account` | `address` |
| `membership` | `organization` |
| `reward_program` | `program` |
| `custom_item` | — |

枚举完整列表以产品内实现为准(登录 / 密码 / 安全备注 / 信用卡 / 身份 / Wi-Fi / API 令牌 / 数据库 / 服务器 / SSH 密钥 / 软件许可等)。

## 4. CustomField 类型(10 种)

| 类型 | UI 默认遮罩 | `value` 语义 |
|------|------------|--------------|
| `text` | 否 | 原样字符串 |
| `password` | 是 | 密码字符串(配生成器与强度评估) |
| `email` | 否 | 邮件地址 |
| `url` | 否 | URL |
| `phone` | 否 | 电话 |
| `date` | 否 | ISO 8601 |
| `otp` | 是 | `otpauth://` URL 或 base32 secret |
| `file` | 否 | `AttachmentRef.id` 字符串 |
| `concealed` | 是 | 通用敏感字符串 |
| `multiline` | 否 | 多行文本 |

## 5. SecurityFlags

| 字段 | 默认 | 含义 |
|------|------|------|
| `require_reauth` | false | 查看 / 编辑前需要重新输入主密码,即使 vault 已解锁 |
| `block_clipboard` | false | 禁止复制到剪贴板 |
| `disable_autofill` | false | 禁止参与浏览器 / 系统自动填充 |
| `local_only` | false | 不参与同步(Phase 2 实装) |

## 6. Schema 版本与迁移

- [`CURRENT_SCHEMA_VERSION`] = 1(随破坏性变更 +1)
- [`MIN_READABLE_SCHEMA_VERSION`] = 1(低于此版本拒绝读)
- 迁移:实现 [`Migration`] trait,注册到 [`Migrator`],按 `from_version → to_version` 链式升级
- 迁移**只**操作 `serde_json::Value`,不依赖具体 Rust 结构体 —— 这样以后改字段不破坏旧数据

## 7. 一致性 / 失败模式

| 场景 | 表现 | 修复 |
|------|------|------|
| `write_item` 成功,`write_manifest` 失败 | item 文件存在但索引漏掉它 | [`VaultManager::rebuild_manifest`] 重建 |
| `move_to_trash` 中途崩溃 | 半完成 rename(原子操作,理论上不应发生) | 操作系统级 rename 是原子的;真出问题就是 FS bug |
| `update_item` 时 archive_to_history 失败 | 旧版本未归档 | history 不完整,业务不影响 |
| 同 vault 多进程并发写 | 后写覆盖,manifest 可能不一致 | MVP 不支持并发,UI 层加进程锁 |

## 8. 不在格式里的东西

- 主密码 / Secret Key:**永不**写盘
- raw KEK / VMK / IKEK / ItemKey 明文:运行时只在 Rust `ZeroizeOnDrop` 结构里
- 任何明文 item body 字段:全部进 `encrypted_blob`

## 9. 测试覆盖

产品主仓的 vault 管理层(闭源)另有 23 个端到端测试,覆盖:

- 创建 → 读取 round-trip
- 更新版本递增 + 历史归档
- stale version → 冲突
- 删除 → 还原 → 永久删
- 永久删必须先经过回收站
- 列表 / 搜索过滤(包含归档 / 包含回收站 / 类型 / tag / favorite)
- 标签增删(重复 / 空白)
- 历史链(创建 + N 次更新后 history 长度)
- 关闭 / 重新打开 vault 后还能解密
- manifest.enc 与 item 文件中**不**包含明文密码 / 标题
- schema_version 在所有持久化对象中 = CURRENT
- rebuild_manifest 从 items/ + trash/ 还原索引
