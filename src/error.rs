//! 加密错误类型。
//!
//! 错误信息**禁止**包含密钥、密码、明文 item。所有变体只描述出错的**类别**,
//! 不携带具体内容。

use thiserror::Error;

/// 所有 crypto_core 公开 API 返回的错误。
#[derive(Debug, Error)]
pub enum CryptoError {
    /// 入参非法(长度不对、参数为零、字符串为空等)。
    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),

    /// KDF 内部错误(参数不被支持或运行时失败)。
    #[error("key derivation failed")]
    KdfFailed,

    /// AEAD 加密失败。
    #[error("encrypt failed")]
    EncryptFailed,

    /// AEAD 解密 / 鉴权失败 —— 可能是密文损坏、密钥错误、AAD 不匹配。
    /// 调用方**禁止**根据本错误细分主密码错 / 数据被篡改,会产生时序侧信道。
    #[error("decrypt or authentication failed")]
    DecryptFailed,

    /// 操作系统 RNG 失败。生产环境上极少发生,一旦发生应停止所有加密操作。
    #[error("system rng failed")]
    RngFailed,

    /// 序列化或反序列化失败。
    #[error("serialization failed")]
    SerializationFailed,

    /// 加密格式版本不被本客户端支持。
    #[error("unsupported format version: {0}")]
    UnsupportedVersion(u16),

    /// Ed25519 签名校验失败 —— 消息被篡改、签名损坏、或公钥不对。
    /// 与 [`CryptoError::DecryptFailed`] 一样不细分原因,防侧信道。
    #[error("signature verification failed")]
    SignatureInvalid,
}

/// `Result` 别名,默认错误是 [`CryptoError`]。
pub type Result<T> = core::result::Result<T, CryptoError>;
