use thiserror::Error;

pub type Result<T> = std::result::Result<T, GatewayError>;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error(transparent)]
    Pingora(#[from] Box<pingora::Error>),

    #[error("Gatewayfile error: {0}")]
    Gatewayfile(String),

    #[error("Certificate cache error: {0}")]
    CertificateCache(String),

    #[error("Reload error: {0}")]
    Reload(String),
}
