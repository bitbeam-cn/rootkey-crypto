//! Argon2id 密钥派生。
//!
//! 输入:
//! - **密码**:UTF-8 NFKD 归一化后的字节,作为 Argon2 的 password(P)参数
//! - **Salt**:32 字节随机,跟 vault 一起持久化
//!
//! 输出:32 字节的 [`MasterUnlockKey`]。
//!
//! ADR-001 后只有 password + salt 单因子,不再有 Secret Key (K) 参数。
//! 为补偿 K 缺失带来的熵下降,默认 memory 提到 128 MiB(远超 OWASP 最低 19 MiB)。

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::keys::{MasterUnlockKey, SymmetricKey};
use crate::random;
// SK 已移除(ADR-001):MUK 由主密码 + salt 直接派生,不再需要 secret_key 作为
// Argon2 的 secret 参数。Argon2id 自身的 memory hardness 是抗暴力破解的核心,
// 默认 memory 128 MiB 补偿 SK 缺失带来的熵下降。

/// 默认 KDF 参数。OWASP 2024 推荐"高安全配置"以上 — 128 MiB 远超 cheat sheet
/// 列出的任意一档,移动端 + 桌面均可承受(派生 ~0.6-1.2s)。
pub const DEFAULT_MEMORY_KIB: u32 = 128 * 1024; // 128 MiB
/// 默认 Argon2id 时间消耗(迭代轮数)。
pub const DEFAULT_TIME_COST: u32 = 3;
/// 默认 Argon2id 并行度(lanes)。
pub const DEFAULT_PARALLELISM: u32 = 4;
/// salt 字节数。
pub const SALT_LEN: usize = 32;

/// 客户端硬编码的最低 KDF 参数下限。低于此值的 vault 直接拒绝解锁,
/// 防止攻击者篡改 vault header 把参数调到不能保护密码的程度。
///
/// 基线对齐 OWASP Password Storage Cheat Sheet (2024+):
/// Argon2id 推荐"最低可接受档" m=19 MiB / t=2 / p=1 (RFC 9106 的 SECOND
/// RECOMMENDED 配置)。任何低于这个组合的参数对单主密码模型(ADR-001)
/// 都不安全,直接拒绝。
pub const MIN_MEMORY_KIB: u32 = 19 * 1024; // 19 MiB(OWASP 2024 cheat sheet 最低)
/// 时间消耗下限。
pub const MIN_TIME_COST: u32 = 2;
/// 并行度下限。
pub const MIN_PARALLELISM: u32 = 1;

/// Argon2id 的支持算法标识。当前只接受 `argon2id`,留枚举是为了后续协议升级。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KdfAlgorithm {
    /// Argon2id,RFC 9106。
    Argon2id,
}

/// 序列化进 vault 的 KDF 参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    /// 算法标识。
    pub algorithm: KdfAlgorithm,
    /// 内存消耗,KiB。
    pub memory_kib: u32,
    /// 时间消耗(迭代)。
    pub time_cost: u32,
    /// 并行度。
    pub parallelism: u32,
    /// 32 字节 salt。
    #[serde(with = "salt_bytes")]
    pub salt: [u8; SALT_LEN],
}

impl KdfParams {
    /// 默认参数 + 全新随机 salt。生产应通过本方法获取参数。
    pub fn generate_default() -> Result<Self> {
        Ok(Self {
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: DEFAULT_MEMORY_KIB,
            time_cost: DEFAULT_TIME_COST,
            parallelism: DEFAULT_PARALLELISM,
            salt: random::bytes::<SALT_LEN>()?,
        })
    }

    /// 校验参数不低于客户端下限,且 salt 不全零。
    pub fn validate(&self) -> Result<()> {
        if self.memory_kib < MIN_MEMORY_KIB
            || self.time_cost < MIN_TIME_COST
            || self.parallelism < MIN_PARALLELISM
        {
            return Err(CryptoError::InvalidArgument(
                "kdf params below client minimum",
            ));
        }
        if self.salt.iter().all(|&b| b == 0) {
            return Err(CryptoError::InvalidArgument("kdf salt all-zero"));
        }
        Ok(())
    }

    /// 用作 AEAD AAD 的 canonical 字节(算法 + 三个数值 + salt)。
    /// 改格式会破坏既有 vault 的解密,**禁止**在不升级 vault 版本的前提下变更。
    pub fn aad_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 4 + 4 + 4 + SALT_LEN);
        out.push(match self.algorithm {
            KdfAlgorithm::Argon2id => 1,
        });
        out.extend_from_slice(&self.memory_kib.to_be_bytes());
        out.extend_from_slice(&self.time_cost.to_be_bytes());
        out.extend_from_slice(&self.parallelism.to_be_bytes());
        out.extend_from_slice(&self.salt);
        out
    }
}

/// 主密码 + KdfParams → [`MasterUnlockKey`]。
///
/// 主密码会被 NFKD 归一化(防止"看上去一样"的不同 codepoint 派生出不同 MUK),
/// 临时缓冲在派生完成后立即清零。
///
/// **ADR-001**:不再接受 `secret_key` 第二因子参数。主密码强度 + Argon2id
/// memory hardness(默认 128 MiB)是 vault 解密的唯一防线,**主密码必须强**
/// (UI 层强制 ≥ 12 位 + zxcvbn score ≥ 3)。
pub fn derive_muk(password: &str, params: &KdfParams) -> Result<MasterUnlockKey> {
    if password.is_empty() {
        return Err(CryptoError::InvalidArgument("password is empty"));
    }
    params.validate()?;

    let argon = match params.algorithm {
        KdfAlgorithm::Argon2id => Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(
                params.memory_kib,
                params.time_cost,
                params.parallelism,
                Some(SymmetricKey::LEN),
            )
            .map_err(|_| CryptoError::KdfFailed)?,
        ),
    };

    let normalized: Zeroizing<String> = Zeroizing::new(password.nfkd().collect());
    let mut output = Zeroizing::new([0u8; SymmetricKey::LEN]);
    argon
        .hash_password_into(normalized.as_bytes(), &params.salt, output.as_mut_slice())
        .map_err(|_| CryptoError::KdfFailed)?;

    let key = SymmetricKey::from_bytes(*output);
    Ok(MasterUnlockKey::from_symmetric(key))
}

mod salt_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::SALT_LEN;

    pub fn serialize<S: Serializer>(
        value: &[u8; SALT_LEN],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; SALT_LEN], D::Error> {
        let v = <Vec<u8>>::deserialize(deserializer)?;
        if v.len() != SALT_LEN {
            return Err(serde::de::Error::custom("salt must be 32 bytes"));
        }
        let mut out = [0u8; SALT_LEN];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_params() -> KdfParams {
        KdfParams {
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: MIN_MEMORY_KIB,
            time_cost: MIN_TIME_COST,
            parallelism: 1,
            salt: [0xAA; SALT_LEN],
        }
    }

    #[test]
    fn defaults_match_spec() {
        let p = KdfParams::generate_default().unwrap();
        // ADR-001 后 memory 提到 128 MiB
        assert_eq!(p.memory_kib, 128 * 1024);
        assert_eq!(p.time_cost, 3);
        assert_eq!(p.parallelism, 4);
        assert_eq!(p.algorithm, KdfAlgorithm::Argon2id);
        assert!(p.salt.iter().any(|&b| b != 0));
    }

    #[test]
    fn rejects_params_below_minimum() {
        let mut p = fixed_params();
        p.memory_kib = 1024; // way below
        assert!(p.validate().is_err());
    }

    /// 边界 — m=19 MiB / t=2 / p=1 是 OWASP 2024 cheat sheet 最低可接受配置,
    /// 必须通过校验。下移一档(m=18 MiB)立即被拒。
    #[test]
    fn owasp_baseline_accepted_one_below_rejected() {
        let mut p = fixed_params();
        p.memory_kib = 19 * 1024;
        p.time_cost = 2;
        p.parallelism = 1;
        assert!(p.validate().is_ok());
        p.memory_kib = 18 * 1024;
        assert!(p.validate().is_err());
    }

    /// 默认参数永远不能被未来重构低于 OWASP 基线 — 编译期检查,不需要 cargo test。
    const _: () = assert!(DEFAULT_MEMORY_KIB >= 19 * 1024);
    const _: () = assert!(DEFAULT_TIME_COST >= 2);
    const _: () = assert!(DEFAULT_PARALLELISM >= 1);

    #[test]
    fn rejects_all_zero_salt() {
        let mut p = fixed_params();
        p.salt = [0; SALT_LEN];
        assert!(p.validate().is_err());
    }

    #[test]
    fn derive_is_deterministic() {
        let p = fixed_params();
        let a = derive_muk("hunter2", &p).unwrap();
        let b = derive_muk("hunter2", &p).unwrap();
        assert_eq!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn different_password_yields_different_muk() {
        let p = fixed_params();
        let a = derive_muk("hunter2", &p).unwrap();
        let b = derive_muk("hunter3", &p).unwrap();
        assert_ne!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn different_salt_yields_different_muk() {
        let mut p1 = fixed_params();
        p1.salt = [0x11; SALT_LEN];
        let mut p2 = fixed_params();
        p2.salt = [0x22; SALT_LEN];
        let a = derive_muk("hunter2", &p1).unwrap();
        let b = derive_muk("hunter2", &p2).unwrap();
        assert_ne!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn rejects_empty_password() {
        assert!(derive_muk("", &fixed_params()).is_err());
    }

    #[test]
    fn aad_bytes_includes_all_fields() {
        let p = fixed_params();
        let bytes = p.aad_bytes();
        assert_eq!(bytes.len(), 1 + 4 + 4 + 4 + SALT_LEN);
        // 修改任一字段都应改变 AAD
        let mut p2 = p.clone();
        p2.time_cost += 1;
        assert_ne!(bytes, p2.aad_bytes());
    }

    #[test]
    fn nfkd_normalization_treats_visually_equal_passwords_as_equal() {
        // "ñ" 可由 NFC(U+00F1) 或 NFD(U+006E U+0303)表达,NFKD 后等价
        let nfc = "ma\u{00F1}ana";
        let nfd = "man\u{0303}ana"; // 故意制造不同的 codepoint
        let p = fixed_params();
        let a = derive_muk(nfc, &p).unwrap();
        let b = derive_muk(nfd, &p).unwrap();
        assert_eq!(a.expose_secret(), b.expose_secret());
    }

    /// KdfParams serde round-trip。
    #[test]
    fn kdf_params_json_round_trip() {
        let p = fixed_params();
        let s = serde_json::to_string(&p).unwrap();
        let back: KdfParams = serde_json::from_str(&s).unwrap();
        assert_eq!(p, back);
    }

    /// salt 字节数不对则反序列化失败。
    #[test]
    fn kdf_params_rejects_wrong_salt_length_on_deserialize() {
        // salt 写成 31 字节而不是 32 应当被拒绝。
        let bad = serde_json::json!({
            "algorithm": "argon2id",
            "memory_kib": MIN_MEMORY_KIB,
            "time_cost": MIN_TIME_COST,
            "parallelism": MIN_PARALLELISM,
            "salt": vec![0u8; SALT_LEN - 1],
        });
        let r: serde_json::Result<KdfParams> = serde_json::from_value(bad);
        assert!(r.is_err());
    }

    /// 拒绝 algorithm 字段未知值。
    #[test]
    fn kdf_params_rejects_unknown_algorithm() {
        let bad = serde_json::json!({
            "algorithm": "scrypt",  // 未来不支持的算法
            "memory_kib": MIN_MEMORY_KIB,
            "time_cost": MIN_TIME_COST,
            "parallelism": MIN_PARALLELISM,
            "salt": vec![0xAAu8; SALT_LEN],
        });
        let r: serde_json::Result<KdfParams> = serde_json::from_value(bad);
        assert!(r.is_err());
    }
}
