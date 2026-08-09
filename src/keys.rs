//! 五层对称密钥的强类型 newtype。
//!
//! 设计原则:
//! - 每种密钥用独立类型,**禁止**互相替代或隐式转换
//! - `Drop` 自动 zeroize
//! - 没有 `Debug` 暴露字节,没有 `Clone`,没有 `Default`,没有 `serde::Serialize`
//! - 唯一拿到字节的方式是 crate 内部的 [`SymmetricKey::expose_secret`],
//!   公开 API 永远以高层包装(包装密钥 / AEAD)操作,不直接给字节
//!
//! 层次:`MUK → KEK → VMK → IKEK → ItemKey`(详见 `docs/SECURITY_MODEL.md`)。

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CryptoError, Result};
use crate::random;

/// 32 字节对称密钥的内部表示。
///
/// 该类型本身**不**对外暴露,所有外部交互通过下方的强类型 newtype。
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SymmetricKey([u8; 32]);

impl SymmetricKey {
    pub(crate) const LEN: usize = 32;

    pub(crate) fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    pub(crate) fn try_from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != Self::LEN {
            return Err(CryptoError::InvalidArgument(
                "symmetric key must be 32 bytes",
            ));
        }
        let mut out = [0u8; Self::LEN];
        out.copy_from_slice(slice);
        Ok(Self(out))
    }

    pub(crate) fn random() -> Result<Self> {
        Ok(Self(random::bytes::<32>()?))
    }

    /// crate 内部使用。**永远不要**把返回的引用复制到长期存储或日志。
    pub(crate) fn expose_secret(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymmetricKey(REDACTED)")
    }
}

/// 给所有 newtype 一次性长出标准方法 + 安全的 Debug 实现。
macro_rules! key_newtype {
    (
        $(#[$attr:meta])*
        $name:ident
    ) => {
        $(#[$attr])*
        #[derive(zeroize::ZeroizeOnDrop)]
        pub struct $name(pub(crate) SymmetricKey);

        impl $name {
            /// 生成一把全新的随机密钥。
            pub fn generate() -> $crate::error::Result<Self> {
                Ok(Self(SymmetricKey::random()?))
            }

            #[allow(dead_code)]
            pub(crate) fn from_symmetric(inner: SymmetricKey) -> Self {
                Self(inner)
            }

            /// **测试 / 同 workspace 其他 crate 内部使用**:暴露 32 字节明文。
            ///
            /// 公开但 `#[doc(hidden)]`。生产业务代码 / FFI 边界 / 日志 / 错误信息
            /// **禁止**调用。返回值生命周期受 `&self` 约束,`self` Drop 时自动 zeroize。
            #[doc(hidden)]
            #[allow(dead_code)]
            pub fn expose_secret(&self) -> &[u8; SymmetricKey::LEN] {
                self.0.expose_secret()
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, concat!(stringify!($name), "(REDACTED)"))
            }
        }
    };
}

key_newtype!(
    /// **MUK** — Master Unlock Key。从主密码 + Secret Key 通过 Argon2id 派生。
    /// 仅用于解开 [`KeyEncryptionKey`]。不参与任何 item 加密。
    MasterUnlockKey
);

key_newtype!(
    /// **ARK** — Account Root Key(ADR-010)。被账户级 MUK 包装,负责包装账户下
    /// **每个** vault 的 KEK。一次解锁(解出 ARK)即可打开账户下全部 vault;
    /// 换主密码只需重新包装 ARK,不触碰任何 vault 链。
    AccountRootKey
);

key_newtype!(
    /// **KEK** — Key Encryption Key。被 MUK 包装,负责包装 VMK。
    ///
    /// 引入 KEK 的原因:换主密码时只需重新包装 KEK(不需要触碰 VMK / 下层),
    /// 见 [`crate::vault::change_master_password`]。
    KeyEncryptionKey
);

key_newtype!(
    /// **VMK** — Vault Master Key。被 KEK 包装,负责包装 IKEK。
    /// 旋转 VMK 时下层 IKEK 会重新包装,但 IKEK 本身的密钥不变,
    /// 因此 item 不需要重新加密。
    VaultMasterKey
);

key_newtype!(
    /// **IKEK** — Item Key Encryption Key。被 VMK 包装,负责包装每条 item 的 [`ItemKey`]。
    ItemKekKey
);

key_newtype!(
    /// **ItemKey** — 每条 item 一把,被 IKEK 包装,负责加密 item payload。
    ItemKey
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_bytes() {
        let k = MasterUnlockKey::generate().unwrap();
        let s = format!("{k:?}");
        assert!(s.contains("REDACTED"));
        assert!(!s.contains(&format!("{:?}", k.expose_secret())));
    }

    #[test]
    fn newtypes_are_distinct_types() {
        // 编译期保证:不同 newtype 不能互相赋值。下面这行如果取消注释会编译失败。
        // let _: KeyEncryptionKey = MasterUnlockKey::generate().unwrap();
        let _ = (
            MasterUnlockKey::generate().unwrap(),
            KeyEncryptionKey::generate().unwrap(),
            VaultMasterKey::generate().unwrap(),
            ItemKekKey::generate().unwrap(),
            ItemKey::generate().unwrap(),
        );
    }

    #[test]
    fn random_keys_are_distinct() {
        let a = MasterUnlockKey::generate().unwrap();
        let b = MasterUnlockKey::generate().unwrap();
        assert_ne!(a.expose_secret(), b.expose_secret());
    }

    /// SymmetricKey::try_from_slice 拒绝长度不为 32 的输入。
    #[test]
    fn symmetric_key_try_from_slice_rejects_wrong_length() {
        assert!(SymmetricKey::try_from_slice(&[0u8; 31]).is_err());
        assert!(SymmetricKey::try_from_slice(&[0u8; 33]).is_err());
        assert!(SymmetricKey::try_from_slice(&[0u8; 32]).is_ok());
    }

    /// SymmetricKey::from_bytes 把 [u8;32] 直接装进去。
    #[test]
    fn symmetric_key_from_bytes_round_trip() {
        let bytes = [0xAB; 32];
        let k = SymmetricKey::from_bytes(bytes);
        assert_eq!(k.expose_secret(), &bytes);
    }
}
