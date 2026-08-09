//! 操作系统 CSPRNG 包装。所有密钥与 nonce 必须从这里取。
//!
//! 本模块不暴露任何可 seed 的 RNG —— 防止误用确定性 RNG 生成密钥。

use crate::error::{CryptoError, Result};

/// 把 OS 随机字节写满 `dst`。失败立刻返回 [`CryptoError::RngFailed`],
/// 调用方**不要**有任何 fallback。
pub fn fill(dst: &mut [u8]) -> Result<()> {
    getrandom::getrandom(dst).map_err(|_| CryptoError::RngFailed)
}

/// 返回 `N` 字节的随机 buffer。便捷方法。
pub fn bytes<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}
