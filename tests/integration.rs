//! 端到端集成测试:模拟用户使用全流程(ADR-001:无 Secret Key)。

use crypto_core::{
    change_master_password, create_vault_keys, decrypt_item, encrypt_item, rotate_vault_key,
    unlock_vault, CryptoError,
};

#[test]
fn full_lifecycle_create_persist_unlock_encrypt_decrypt() {
    // 1. 创建 vault
    let created = create_vault_keys("hunter2-stronger-please").unwrap();

    // 2. 加密多条 item
    let plaintexts: &[&[u8]] = &[
        b"github / alice / hunter2",
        b"aws / api-key / abcdef0123456789",
        b"note / wifi password",
    ];
    let blobs: Vec<_> = plaintexts
        .iter()
        .enumerate()
        .map(|(i, p)| encrypt_item(p, &[i as u8; 16], &created.unlocked).unwrap())
        .collect();

    // 3. 持久化(JSON 模拟)
    let keyset_json = serde_json::to_string(&created.encrypted).unwrap();
    let blobs_json: Vec<_> = blobs
        .iter()
        .map(|b| serde_json::to_string(b).unwrap())
        .collect();

    // 4. 模拟"重启":丢内存,从持久化反序列化
    drop(created);
    let parsed_keyset: crypto_core::EncryptedKeySet = serde_json::from_str(&keyset_json).unwrap();
    let parsed_blobs: Vec<crypto_core::EncryptedItemBlob> = blobs_json
        .iter()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();

    // 5. 用主密码解锁(无 SK)
    let unlocked = unlock_vault("hunter2-stronger-please", &parsed_keyset).unwrap();

    // 6. 解密所有 item,逐字节匹配
    for (i, (blob, expected)) in parsed_blobs.iter().zip(plaintexts.iter()).enumerate() {
        let decrypted = decrypt_item(blob, &[i as u8; 16], &unlocked).unwrap();
        assert_eq!(decrypted.as_slice(), *expected);
    }
}

#[test]
fn change_password_then_decrypt_old_items() {
    let created = create_vault_keys("old-pw").unwrap();
    let blob = encrypt_item(b"important", &[7u8; 16], &created.unlocked).unwrap();

    let new_keyset =
        change_master_password("old-pw", "new-stronger-pw", &created.encrypted).unwrap();

    // 旧密码不再能解锁
    assert!(matches!(
        unlock_vault("old-pw", &new_keyset),
        Err(CryptoError::DecryptFailed)
    ));

    // 新密码可以解锁,且历史 item 仍然可解
    let unlocked = unlock_vault("new-stronger-pw", &new_keyset).unwrap();
    let decrypted = decrypt_item(&blob, &[7u8; 16], &unlocked).unwrap();
    assert_eq!(decrypted.as_slice(), b"important");
}

#[test]
fn rotate_vault_key_keeps_items_decryptable() {
    let created = create_vault_keys("pw").unwrap();
    let blob = encrypt_item(b"persistent secret", &[8u8; 16], &created.unlocked).unwrap();

    let (new_keyset, new_unlocked, _) =
        rotate_vault_key(&created.unlocked, &created.encrypted, None).unwrap();

    let decrypted = decrypt_item(&blob, &[8u8; 16], &new_unlocked).unwrap();
    assert_eq!(decrypted.as_slice(), b"persistent secret");

    let unlocked_again = unlock_vault("pw", &new_keyset).unwrap();
    let decrypted_again = decrypt_item(&blob, &[8u8; 16], &unlocked_again).unwrap();
    assert_eq!(decrypted_again.as_slice(), b"persistent secret");
}

#[test]
fn json_round_trip_persistent_storage() {
    let created = create_vault_keys("pw").unwrap();
    let json = serde_json::to_string_pretty(&created.encrypted).unwrap();
    let parsed: crypto_core::EncryptedKeySet = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, created.encrypted);
}
