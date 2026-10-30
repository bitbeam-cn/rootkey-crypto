//! 共享保险库挂进账户(ADR-003 补完,2026-10-29)。
//!
//! 共享保险库在每个成员本机都是一个**普通的账户内保险库**:目录结构、条目加密、同步全跟
//! 个人库一样。差别只在 VMK / IKEK 从哪来 —— 个人库随机生成,共享库由成员间分发的
//! `shared_vault_key`(members.json 里每人一份 sealed box)派生,所以每个成员算出同一对。
//!
//! 能这样做的前提:条目密钥、条目密文、签名种子、IKEK 包装的 AAD 只绑 `vault_id`
//! (见 `vault.rs` 的 `aad_for_*`),不绑账户;只有 KEK → VMK 这一层绑了账户 ID。
//! 于是每个成员用**自己账户**新生成的 KEK 包同一份 VMK,解锁时跟自己的库一起打开。

use zeroize::Zeroize;

use crate::account::{aad_for_vault_kek, AccountVaultEntry, UnlockedAccount, VaultKeySlot, VaultUnderAccount, ACCOUNT_FORMAT_VERSION};
use crate::aead::wrap_key;
use crate::error::Result;
use crate::keys::{ItemKekKey, KeyEncryptionKey, SymmetricKey, VaultMasterKey};
use crate::vault::{aad_for_ikek, aad_for_vmk, Id, UnlockedVault};

/// 由 `shared_vault_key` 派生共享库的 VMK / IKEK。输入绑 `vault_id`:同一把钥匙挪到别的库上
/// 派生出的是另一对,防跨库复用。
fn derive_shared_vault_keys(shared_vault_key: &[u8; 32], vault_id: &Id) -> (VaultMasterKey, ItemKekKey) {
    let mut material = Vec::with_capacity(48);
    material.extend_from_slice(shared_vault_key);
    material.extend_from_slice(vault_id);
    let mut vmk = blake3::derive_key("root-key/shared-vault-vmk/v1", &material);
    let mut ikek = blake3::derive_key("root-key/shared-vault-ikek/v1", &material);
    material.zeroize();
    let out = (
        VaultMasterKey::from_symmetric(SymmetricKey::from_bytes(vmk)),
        ItemKekKey::from_symmetric(SymmetricKey::from_bytes(ikek)),
    );
    vmk.zeroize();
    ikek.zeroize();
    out
}

/// 用给定的 VMK / IKEK 在本账户下新包一层(新 KEK)。
fn wrap_under_account(
    account: &UnlockedAccount,
    vault_id: Id,
    vmk: VaultMasterKey,
    ikek: ItemKekKey,
) -> Result<VaultUnderAccount> {
    let kek = KeyEncryptionKey::generate()?;
    let wrapped_kek = wrap_key(&account.ark.0, &kek.0, &aad_for_vault_kek(&account.account_id, &vault_id))?;
    let wrapped_vmk = wrap_key(&kek.0, &vmk.0, &aad_for_vmk(&account.account_id, &vault_id))?;
    let wrapped_ikek = wrap_key(&vmk.0, &ikek.0, &aad_for_ikek(&vault_id))?;
    Ok(VaultUnderAccount {
        entry: AccountVaultEntry { vault_id, wrapped_kek },
        slot: VaultKeySlot {
            version: ACCOUNT_FORMAT_VERSION,
            account_id: account.account_id,
            vault_id,
            wrapped_vmk,
            wrapped_ikek,
        },
        unlocked: UnlockedVault { account_id: account.account_id, vault_id, kek, vmk, ikek },
    })
}

/// 把共享保险库挂进本账户。建库的人、后来加入的人都走这一条;移出成员换过钥匙后,
/// 每个留下的成员用新的 `shared_vault_key` 再挂一次。
///
/// 调用方把 `entry` 写进 `AccountKeySet::vaults`(同 vault_id 的旧记录要替换掉),
/// `slot` 写进库目录。
pub fn attach_shared_vault_under_account(
    account: &UnlockedAccount,
    vault_id: Id,
    shared_vault_key: &[u8; 32],
) -> Result<VaultUnderAccount> {
    let (vmk, ikek) = derive_shared_vault_keys(shared_vault_key, &vault_id);
    wrap_under_account(account, vault_id, vmk, ikek)
}

/// 共享保险库换钥匙(移出成员后):沿用本机 KEK,VMK / IKEK 改由新的 `shared_vault_key` 派生。
///
/// 账户里那条挂载记录(包着 KEK)不用动,只换库目录里的 keyslot —— 换库目录是一次改名,
/// 中途崩了也好收拾。返回新 keyslot 和新的解锁句柄。
pub fn rotate_shared_vault_keys(
    vault: &UnlockedVault,
    new_shared_vault_key: &[u8; 32],
) -> Result<(VaultKeySlot, UnlockedVault)> {
    let vault_id = vault.vault_id;
    let (vmk, ikek) = derive_shared_vault_keys(new_shared_vault_key, &vault_id);
    let kek = KeyEncryptionKey::from_symmetric(SymmetricKey::from_bytes(*vault.kek.0.expose_secret()));
    let slot = VaultKeySlot {
        version: ACCOUNT_FORMAT_VERSION,
        account_id: vault.account_id,
        vault_id,
        wrapped_vmk: wrap_key(&kek.0, &vmk.0, &aad_for_vmk(&vault.account_id, &vault_id))?,
        wrapped_ikek: wrap_key(&vmk.0, &ikek.0, &aad_for_ikek(&vault_id))?,
    };
    Ok((slot, UnlockedVault { account_id: vault.account_id, vault_id, kek, vmk, ikek }))
}

/// 把一个已解开的库重新挂到(换过 ARK 的)账户下:新 KEK,VMK / IKEK 原样。
///
/// 换整条密钥链(ADR-014)时给共享保险库用 —— 它的 VMK / IKEK 是全体成员共用的,
/// 只能换本机这一层包装,换了 VMK 别人就读不了你写的内容了。
pub fn reattach_vault_under_account(
    account: &UnlockedAccount,
    vault: &UnlockedVault,
) -> Result<VaultUnderAccount> {
    let vmk = VaultMasterKey::from_symmetric(SymmetricKey::from_bytes(*vault.vmk.0.expose_secret()));
    let ikek = ItemKekKey::from_symmetric(SymmetricKey::from_bytes(*vault.ikek.0.expose_secret()));
    wrap_under_account(account, vault.vault_id, vmk, ikek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{create_account, unlock_account_vault};
    use crate::item::{decrypt_item, encrypt_item};

    const VAULT: Id = [7u8; 16];
    const ITEM: [u8; 16] = [9u8; 16];

    #[test]
    fn two_accounts_read_each_others_items() {
        let alice = create_account("pw-alice").unwrap();
        let bob = create_account("pw-bob").unwrap();
        let key = [42u8; 32];
        let a = attach_shared_vault_under_account(&alice.unlocked, VAULT, &key).unwrap();
        let b = attach_shared_vault_under_account(&bob.unlocked, VAULT, &key).unwrap();
        // 各自的 KEK 不同(包装绑各自账户)……
        assert_ne!(a.entry.wrapped_kek, b.entry.wrapped_kek);
        // ……但 Alice 写的 Bob 能读,反之亦然
        let blob = encrypt_item(b"netflix", &ITEM, &a.unlocked).unwrap();
        assert_eq!(&decrypt_item(&blob, &ITEM, &b.unlocked).unwrap()[..], b"netflix");
        let blob = encrypt_item(b"wifi", &ITEM, &b.unlocked).unwrap();
        assert_eq!(&decrypt_item(&blob, &ITEM, &a.unlocked).unwrap()[..], b"wifi");
    }

    #[test]
    fn attached_vault_unlocks_through_the_account() {
        let alice = create_account("pw-alice").unwrap();
        let a = attach_shared_vault_under_account(&alice.unlocked, VAULT, &[1u8; 32]).unwrap();
        let reopened = unlock_account_vault(&alice.unlocked, &a.entry, &a.slot).unwrap();
        let blob = encrypt_item(b"x", &ITEM, &a.unlocked).unwrap();
        assert_eq!(&decrypt_item(&blob, &ITEM, &reopened).unwrap()[..], b"x");
    }

    #[test]
    fn rotated_key_cannot_read_old_items() {
        let alice = create_account("pw-alice").unwrap();
        let old = attach_shared_vault_under_account(&alice.unlocked, VAULT, &[1u8; 32]).unwrap();
        let new = attach_shared_vault_under_account(&alice.unlocked, VAULT, &[2u8; 32]).unwrap();
        let blob = encrypt_item(b"x", &ITEM, &new.unlocked).unwrap();
        assert!(decrypt_item(&blob, &ITEM, &old.unlocked).is_err());
    }

    #[test]
    fn rotation_keeps_the_account_entry_and_matches_a_fresh_attach() {
        let alice = create_account("pw-alice").unwrap();
        let bob = create_account("pw-bob").unwrap();
        let a = attach_shared_vault_under_account(&alice.unlocked, VAULT, &[1u8; 32]).unwrap();
        let (slot, rotated) = rotate_shared_vault_keys(&a.unlocked, &[2u8; 32]).unwrap();
        // 账户挂载记录不变,换的只是 keyslot
        let reopened = unlock_account_vault(&alice.unlocked, &a.entry, &slot).unwrap();
        // Bob 用新钥匙新挂一次,和 Alice 换完的读写互通
        let b = attach_shared_vault_under_account(&bob.unlocked, VAULT, &[2u8; 32]).unwrap();
        let blob = encrypt_item(b"after", &ITEM, &rotated).unwrap();
        assert_eq!(&decrypt_item(&blob, &ITEM, &b.unlocked).unwrap()[..], b"after");
        assert_eq!(&decrypt_item(&blob, &ITEM, &reopened).unwrap()[..], b"after");
    }

    #[test]
    fn same_key_on_another_vault_id_derives_other_keys() {
        let alice = create_account("pw-alice").unwrap();
        let a = attach_shared_vault_under_account(&alice.unlocked, VAULT, &[1u8; 32]).unwrap();
        let other = attach_shared_vault_under_account(&alice.unlocked, [8u8; 16], &[1u8; 32]).unwrap();
        assert_ne!(a.unlocked.ikek.0.expose_secret(), other.unlocked.ikek.0.expose_secret());
    }

    #[test]
    fn reattach_keeps_shared_keys_under_a_new_account_root() {
        let alice = create_account("pw-alice").unwrap();
        let a = attach_shared_vault_under_account(&alice.unlocked, VAULT, &[1u8; 32]).unwrap();
        let blob = encrypt_item(b"x", &ITEM, &a.unlocked).unwrap();
        // 换过 ARK 的同一账户(ADR-014 rekey 后)
        let rotated = create_account("pw-new").unwrap();
        let rotated = UnlockedAccount { account_id: alice.unlocked.account_id, ark: rotated.unlocked.ark };
        let re = reattach_vault_under_account(&rotated, &a.unlocked).unwrap();
        let reopened = unlock_account_vault(&rotated, &re.entry, &re.slot).unwrap();
        assert_eq!(&decrypt_item(&blob, &ITEM, &reopened).unwrap()[..], b"x");
        assert!(unlock_account_vault(&alice.unlocked, &re.entry, &re.slot).is_err());
    }
}
