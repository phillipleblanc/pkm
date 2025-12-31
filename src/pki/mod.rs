pub mod pem;
pub mod wrapped;
pub mod x509;

use std::time::{Duration, SystemTime};

use const_oid::ObjectIdentifier;
use p256::ecdsa::VerifyingKey as P256VerifyingKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::{OsRng, RngCore};
use sha1::Sha1;
use sha1::Digest as Sha1Digest;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use crate::app::error::AppError;

pub use pem::{private_key_pem_bytes, write_cert_pem};
pub use wrapped::{is_wrapped_key, read_wrapped_key_bytes, write_wrapped_key};
pub use x509::{build_leaf_cert, build_root_ca};

pub fn name_from_cn_ou(common_name: &str, organizational_unit: &str) -> Result<Name, AppError> {
    let subject = format!("CN={},OU={}", common_name, organizational_unit);
    Ok(subject.parse()?)
}

pub fn validity_from_now_days(days: u32, skew: bool) -> Result<Validity, AppError> {
    let now = SystemTime::now();
    let not_before = if skew {
        now - Duration::from_secs(300)
    } else {
        now
    };
    let not_after = now + Duration::from_secs(days as u64 * 24 * 60 * 60);

    Ok(Validity {
        not_before: Time::try_from(not_before)?,
        not_after: Time::try_from(not_after)?,
    })
}

pub fn random_serial() -> Result<SerialNumber, AppError> {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    if bytes.iter().all(|b| *b == 0) {
        bytes[15] = 1;
    }
    Ok(SerialNumber::new(&bytes)?)
}

pub fn generate_leaf_key() -> Result<p256::SecretKey, AppError> {
    Ok(p256::SecretKey::random(&mut OsRng))
}

pub fn spki_from_leaf_key(key: &p256::SecretKey) -> Result<spki::SubjectPublicKeyInfoOwned, AppError> {
    let public_key = key.public_key();
    let encoded = public_key.to_encoded_point(false);
    let verifying = P256VerifyingKey::from_encoded_point(&encoded)
        .map_err(|_| AppError::X509("invalid leaf public key".to_string()))?;
    Ok(spki::SubjectPublicKeyInfoOwned::from_key(verifying)?)
}

pub fn spki_from_hsm_public_key(
    public_key: &yubihsm::asymmetric::PublicKey,
) -> Result<spki::SubjectPublicKeyInfoOwned, AppError> {
    match public_key.algorithm {
        yubihsm::asymmetric::Algorithm::EcP256 => {
            let point = public_key
                .ecdsa::<p256::NistP256>()
                .ok_or_else(|| AppError::X509("invalid P-256 public key".to_string()))?;
            let verifying = P256VerifyingKey::from_encoded_point(&point)
                .map_err(|_| AppError::X509("invalid P-256 public key".to_string()))?;
            Ok(spki::SubjectPublicKeyInfoOwned::from_key(verifying)?)
        }
        _ => Err(AppError::Usage(
            "unsupported HSM public key algorithm".to_string(),
        )),
    }
}

pub fn signature_algorithm_identifier(
    algorithm: yubihsm::asymmetric::Algorithm,
) -> Result<spki::AlgorithmIdentifierOwned, AppError> {
    let oid = match algorithm {
        yubihsm::asymmetric::Algorithm::EcP256 => ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
        yubihsm::asymmetric::Algorithm::EcP384 => ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"),
        _ => {
            return Err(AppError::Usage(
                "unsupported CA key algorithm for signing".to_string(),
            ))
        }
    };

    Ok(spki::AlgorithmIdentifierOwned {
        oid,
        parameters: None,
    })
}

pub fn signature_name(algorithm: yubihsm::asymmetric::Algorithm) -> &'static str {
    match algorithm {
        yubihsm::asymmetric::Algorithm::EcP256 => "ecdsa-p256-sha256",
        yubihsm::asymmetric::Algorithm::EcP384 => "ecdsa-p384-sha384",
        _ => "unknown",
    }
}

pub fn key_identifier_from_spki(
    spki: &spki::SubjectPublicKeyInfoOwned,
) -> Result<der::asn1::OctetString, AppError> {
    let bytes = spki.subject_public_key.raw_bytes();
    let digest = Sha1::digest(bytes);
    Ok(der::asn1::OctetString::new(digest.as_slice())?)
}
