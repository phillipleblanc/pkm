use std::path::Path;

use der::EncodePem;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use x509_cert::Certificate;

use crate::app::error::AppError;

pub fn write_cert_pem(path: &Path, cert: &Certificate) -> Result<(), AppError> {
    let pem = cert.to_pem(LineEnding::LF)?;
    std::fs::write(path, pem.as_bytes())?;
    Ok(())
}

pub fn private_key_pem_bytes(key: &p256::SecretKey) -> Result<Vec<u8>, AppError> {
    let pem = key.to_pkcs8_pem(LineEnding::LF)?;
    Ok(pem.as_bytes().to_vec())
}
