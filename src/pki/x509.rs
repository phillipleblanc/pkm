use der::asn1::{BitString, Ia5String};
use der::Encode;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName,
    SubjectKeyIdentifier,
};
use x509_cert::ext::{AsExtension, Extensions};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use crate::app::error::AppError;
use crate::cli::TlsAddArgs;
use crate::pki::key_identifier_from_spki;

pub fn build_root_ca<F>(
    subject: Name,
    serial: SerialNumber,
    validity: Validity,
    subject_spki: spki::SubjectPublicKeyInfoOwned,
    signature_alg: spki::AlgorithmIdentifierOwned,
    sign_fn: F,
) -> Result<Certificate, AppError>
where
    F: Fn(&[u8]) -> Result<Vec<u8>, AppError>,
{
    let ski = SubjectKeyIdentifier(key_identifier_from_spki(&subject_spki)?);
    let aki = AuthorityKeyIdentifier {
        key_identifier: Some(key_identifier_from_spki(&subject_spki)?),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };

    let key_usage = KeyUsage((KeyUsages::KeyCertSign | KeyUsages::CRLSign).into());
    let basic_constraints = BasicConstraints {
        ca: true,
        path_len_constraint: None,
    };

    let mut extensions = Extensions::new();
    extensions.push(basic_constraints.to_extension(&subject, &extensions)?);
    extensions.push(key_usage.to_extension(&subject, &extensions)?);
    extensions.push(ski.to_extension(&subject, &extensions)?);
    extensions.push(aki.to_extension(&subject, &extensions)?);

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: serial,
        signature: signature_alg.clone(),
        issuer: subject.clone(),
        validity,
        subject,
        subject_public_key_info: subject_spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };

    sign_certificate(tbs, signature_alg, sign_fn)
}

pub fn build_leaf_cert<F>(
    subject: Name,
    issuer: Name,
    serial: SerialNumber,
    validity: Validity,
    subject_spki: spki::SubjectPublicKeyInfoOwned,
    issuer_spki: spki::SubjectPublicKeyInfoOwned,
    signature_alg: spki::AlgorithmIdentifierOwned,
    tls_args: &TlsAddArgs,
    sign_fn: F,
) -> Result<Certificate, AppError>
where
    F: Fn(&[u8]) -> Result<Vec<u8>, AppError>,
{
    if !tls_args.client && !tls_args.server {
        return Err(AppError::Usage(
            "at least one of --client or --server is required".to_string(),
        ));
    }

    let ski = SubjectKeyIdentifier(key_identifier_from_spki(&subject_spki)?);
    let aki = AuthorityKeyIdentifier {
        key_identifier: Some(key_identifier_from_spki(&issuer_spki)?),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };

    let basic_constraints = BasicConstraints {
        ca: false,
        path_len_constraint: None,
    };

    let key_usage = KeyUsage(KeyUsages::DigitalSignature.into());

    let mut eku = Vec::new();
    if tls_args.client {
        eku.push(const_oid::db::rfc5280::ID_KP_CLIENT_AUTH);
    }
    if tls_args.server {
        eku.push(const_oid::db::rfc5280::ID_KP_SERVER_AUTH);
    }
    let extended_key_usage = ExtendedKeyUsage(eku);

    let mut san = Vec::new();
    for host in &tls_args.hosts {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            san.push(x509_cert::ext::pkix::name::GeneralName::from(ip));
        } else {
            san.push(x509_cert::ext::pkix::name::GeneralName::DnsName(
                Ia5String::new(host)?,
            ));
        }
    }
    let subject_alt_name = SubjectAltName(san);

    let mut extensions = Extensions::new();
    extensions.push(basic_constraints.to_extension(&subject, &extensions)?);
    extensions.push(key_usage.to_extension(&subject, &extensions)?);
    extensions.push(extended_key_usage.to_extension(&subject, &extensions)?);
    if !tls_args.hosts.is_empty() {
        extensions.push(subject_alt_name.to_extension(&subject, &extensions)?);
    }
    extensions.push(ski.to_extension(&subject, &extensions)?);
    extensions.push(aki.to_extension(&subject, &extensions)?);

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: serial,
        signature: signature_alg.clone(),
        issuer,
        validity,
        subject,
        subject_public_key_info: subject_spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };

    sign_certificate(tbs, signature_alg, sign_fn)
}

fn sign_certificate<F>(
    tbs: TbsCertificate,
    signature_alg: spki::AlgorithmIdentifierOwned,
    sign_fn: F,
) -> Result<Certificate, AppError>
where
    F: Fn(&[u8]) -> Result<Vec<u8>, AppError>,
{
    let tbs_der = tbs.to_der()?;
    let sig_der = sign_fn(&tbs_der)?;
    let signature = BitString::from_bytes(&sig_der)?;

    Ok(Certificate {
        tbs_certificate: tbs,
        signature_algorithm: signature_alg,
        signature,
    })
}
