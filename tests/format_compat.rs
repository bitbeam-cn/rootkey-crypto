//! 历史格式回归测试 —— 保证「用户的老库，新版 App 还打得开」。
//!
//! ## 这个文件存在的理由
//!
//! 保险库数据比软件活得久。用户 8 月建的库，明年装的 App 也得能打开它。
//! 而格式兼容是那种**坏了不会立刻被发现**的东西:改一行 AAD 构造、改一个字段名、
//! 给结构体加个 `#[serde(deny_unknown_fields)]`，本地跑一遍全绿(因为本地的库是
//! 新代码刚建的)，等发到用户手上才炸。
//!
//! 唯一挡得住的办法:**把历史格式的真实产物冻在仓库里**，每次 CI 用当前代码打开它。
//!
//! ## 加新 fixture 的步骤(下次升 FORMAT_VERSION 时)
//!
//! 1. 在**升版本之前**的那个 commit 上,跑:
//!    `cargo test -p crypto_core --test format_compat -- --ignored generate_fixture`
//! 2. 把 `tests/fixtures/account-v<N>/` 提交进仓库
//! 3. 照下面 `v2_fixture_still_unlocks` 的样子加一个 `v<N>_fixture_still_unlocks`
//! 4. **老的测试一个都不许删** —— 删掉就等于宣布不再支持那个版本的用户
//!
//! ## fixture 里没有秘密
//!
//! 主密码是写死的测试串,内容是 `b"fixture-plaintext-payload"`。
//! 它是密文,但密钥就在旁边 —— 不要往里放任何真实数据。

use std::path::{Path, PathBuf};

use crypto_core::{
    create_account, create_vault_under_account, decrypt_item, encrypt_item, unlock_account,
    unlock_account_vault, AccountKeySet, AccountVaultEntry, EncryptedItemBlob, VaultKeySlot,
};

/// fixture 用的主密码。**不是任何真实密码**,故意写死以便测试可复现。
const FIXTURE_PASSWORD: &str = "fixture-master-password-do-not-reuse";
/// fixture 里那条 item 的明文。
const FIXTURE_PLAINTEXT: &[u8] = b"fixture-plaintext-payload";
/// fixture 里那条 item 的 id(固定,因为 v3 起 AAD 绑 item_id,换 id 就解不开)。
const FIXTURE_ITEM_ID: [u8; 16] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];

fn fixture_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// 用当前代码生成一份 fixture。**平时不跑**(`#[ignore]`),只在升格式版本前手动跑一次。
///
/// 跑法:
/// ```text
/// cargo test -p crypto_core --test format_compat -- --ignored generate_fixture
/// ```
#[test]
#[ignore = "只在升格式版本前手动生成 fixture 时跑"]
fn generate_fixture() {
    let acct = create_account(FIXTURE_PASSWORD).expect("create_account");
    let vault = create_vault_under_account(&acct.unlocked).expect("create_vault_under_account");

    let mut keyset = acct.encrypted;
    keyset.vaults.push(vault.entry.clone());

    let blob = encrypt_item(FIXTURE_PLAINTEXT, &FIXTURE_ITEM_ID, &vault.unlocked).expect("encrypt");

    let dir = fixture_dir(&format!("account-v{}", keyset.version));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let w = |name: &str, v: &dyn erased::Ser| {
        std::fs::write(dir.join(name), v.to_pretty()).expect("write fixture");
    };
    w("account.json", &keyset);
    w("keyslot.json", &vault.slot);
    w("item.json", &blob);

    eprintln!("fixture 已生成到 {}", dir.display());
    eprintln!("请把这个目录提交进仓库,并加一条对应的 *_fixture_still_unlocks 测试");
}

/// 极小的序列化擦除层 —— 只为让上面的 `w` 闭包能收不同类型。
mod erased {
    pub trait Ser {
        fn to_pretty(&self) -> Vec<u8>;
    }
    impl<T: serde::Serialize> Ser for T {
        fn to_pretty(&self) -> Vec<u8> {
            let mut v = serde_json::to_vec_pretty(self).expect("serialize fixture");
            v.push(b'\n');
            v
        }
    }
}

/// 读 fixture 并跑完整解锁链:主密码 → 账户 → vault → item 明文。
fn assert_fixture_unlocks(name: &str) {
    let dir = fixture_dir(name);
    assert!(
        dir.is_dir(),
        "fixture 目录不存在: {} —— 它必须随代码一起进仓库",
        dir.display()
    );

    let read = |f: &str| std::fs::read(dir.join(f)).unwrap_or_else(|e| panic!("读 {f} 失败: {e}"));
    let keyset: AccountKeySet = serde_json::from_slice(&read("account.json")).expect("account.json");
    let slot: VaultKeySlot = serde_json::from_slice(&read("keyslot.json")).expect("keyslot.json");
    let blob: EncryptedItemBlob = serde_json::from_slice(&read("item.json")).expect("item.json");

    // 1. 主密码解开账户 —— 这一步覆盖 KDF 参数、盐、wrapped_ark 的 AAD 构造
    let account = unlock_account(FIXTURE_PASSWORD, &keyset)
        .expect("老 fixture 用正确主密码解不开账户了 —— 格式兼容已破");

    // 2. 账户解开 vault —— 覆盖 KEK/VMK/IKEK 三层包装与各自的 AAD
    let entry: &AccountVaultEntry = keyset
        .vaults
        .iter()
        .find(|e| e.vault_id == slot.vault_id)
        .expect("fixture 的 account.json 里找不到对应 vault entry");
    let unlocked =
        unlock_account_vault(&account, entry, &slot).expect("老 fixture 的 vault 解不开了");

    // 3. 解 item —— 覆盖 item 封装格式与绑 item_id 的 AAD
    let plain = decrypt_item(&blob, &FIXTURE_ITEM_ID, &unlocked).expect("老 fixture 的 item 解不开了");
    assert_eq!(
        plain.as_slice(),
        FIXTURE_PLAINTEXT,
        "解出来的明文和存进去的不一致"
    );
}

/// v2 账户格式 + v3 item 格式 —— 2026-09 线上在跑的那一版。
///
/// 这份 fixture 对应真实用户手里的数据。**它挂了就意味着存量用户打不开自己的库。**
#[test]
fn v2_fixture_still_unlocks() {
    assert_fixture_unlocks("account-v2");
}

/// 错误的主密码必须解不开 —— 防止上面的测试因为"什么都能解开"而变成假绿灯。
#[test]
fn v2_fixture_rejects_wrong_password() {
    let dir = fixture_dir("account-v2");
    let keyset: AccountKeySet =
        serde_json::from_slice(&std::fs::read(dir.join("account.json")).expect("read"))
            .expect("parse");
    assert!(
        unlock_account("definitely-not-the-fixture-password", &keyset).is_err(),
        "错误主密码竟然解开了 —— 上面的兼容性测试等于没测"
    );
}

/// 数据**比 App 新** → [`CryptoError::UnsupportedVersion`](用户该升级 App)。
///
/// 这条和下一条把「两个方向报不同的错」钉死。它们曾经是同一个错误,
/// 而两者的用户指引正好相反 —— 一个让往新装,一个让往旧装,
/// 合成一条文案必然误导其中一半人。
#[test]
fn newer_schema_reports_unsupported_version() {
    let dir = fixture_dir("account-v2");
    let mut keyset: AccountKeySet =
        serde_json::from_slice(&std::fs::read(dir.join("account.json")).expect("read"))
            .expect("parse");
    keyset.version = u16::MAX; // 假装是未来版本写的
    match unlock_account(FIXTURE_PASSWORD, &keyset) {
        Err(crypto_core::CryptoError::UnsupportedVersion(v)) => assert_eq!(v, u16::MAX),
        other => panic!("数据比 App 新时应报 UnsupportedVersion,实际: {other:?}"),
    }
}

/// 数据**比 App 能读的最老版本还老** → [`CryptoError::SchemaTooOld`]
/// (用户该先用中间版本打开一次)。
#[test]
fn older_schema_reports_schema_too_old() {
    let dir = fixture_dir("account-v2");
    let mut keyset: AccountKeySet =
        serde_json::from_slice(&std::fs::read(dir.join("account.json")).expect("read"))
            .expect("parse");
    keyset.version = 1; // 低于 ACCOUNT_MIN_READABLE_VERSION
    match unlock_account(FIXTURE_PASSWORD, &keyset) {
        Err(crypto_core::CryptoError::SchemaTooOld(v)) => assert_eq!(v, 1),
        other => panic!("数据比 App 老时应报 SchemaTooOld,实际: {other:?}"),
    }
}
