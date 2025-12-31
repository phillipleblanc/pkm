use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("pkm is not configured yet — run `pkm init` first")]
    NotConfigured,

    #[error("AuthKey password not found in keyring; re-run `pkm init`")]
    MissingKeyring,

    #[error("HSM error: {0}")]
    Hsm(String),

    #[error("Keyring error: {0}")]
    Keyring(String),

    #[error("Filesystem error: {0}")]
    Io(#[from] io::Error),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Usage error: {0}")]
    Usage(String),

    #[error("X.509 error: {0}")]
    X509(String),
}

impl AppError {
    pub fn exit_code(&self) -> i32 {
        match self {
            AppError::NotConfigured => 3,
            AppError::MissingKeyring => 5,
            AppError::Hsm(_) => 4,
            AppError::Keyring(_) => 5,
            AppError::Io(_) => 5,
            AppError::Config(_) => 5,
            AppError::Usage(_) => 2,
            AppError::X509(_) => 5,
        }
    }
}

impl From<keyring::Error> for AppError {
    fn from(err: keyring::Error) -> Self {
        match err {
            keyring::Error::NoEntry => AppError::MissingKeyring,
            other => AppError::Keyring(other.to_string()),
        }
    }
}

impl From<yubihsm::client::Error> for AppError {
    fn from(err: yubihsm::client::Error) -> Self {
        AppError::Hsm(err.to_string())
    }
}

impl From<der::Error> for AppError {
    fn from(err: der::Error) -> Self {
        AppError::X509(err.to_string())
    }
}

impl From<spki::Error> for AppError {
    fn from(err: spki::Error) -> Self {
        AppError::X509(err.to_string())
    }
}

impl From<p256::pkcs8::Error> for AppError {
    fn from(err: p256::pkcs8::Error) -> Self {
        AppError::X509(err.to_string())
    }
}

impl From<toml::de::Error> for AppError {
    fn from(err: toml::de::Error) -> Self {
        AppError::Config(err.to_string())
    }
}

impl From<toml::ser::Error> for AppError {
    fn from(err: toml::ser::Error) -> Self {
        AppError::Config(err.to_string())
    }
}
