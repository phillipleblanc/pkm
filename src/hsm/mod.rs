use std::str::FromStr;

use sha2::{Digest, Sha256, Sha384};
use yubihsm::asymmetric::Algorithm;
use yubihsm::connector::usb::{UsbConfig, UsbConnector};
use yubihsm::{authentication, hmac, otp};
use yubihsm::{object, wrap, Algorithm as HsmAlgorithm, Capability, Client, Credentials, Domain};

use crate::app::config::AppConfig;
use crate::app::error::AppError;

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub id: u16,
    pub label: String,
    pub algorithm: Algorithm,
}

#[derive(Debug, Clone)]
pub struct KeyListEntry {
    pub id: u16,
    pub label: String,
    pub object_type: object::Type,
    pub algorithm: HsmAlgorithm,
}

pub const TLS_WRAP_KEY_LABEL: &str = "pkm-tls-wrap";

pub fn connect_usb(config: &AppConfig, password: &str) -> Result<Client, AppError> {
    let mut usb_config = UsbConfig::default();
    if let Some(serial) = config.hsm.serial {
        let serial_str = format!("{:010}", serial);
        let serial_num = yubihsm::device::SerialNumber::from_str(&serial_str)
            .map_err(|e| AppError::Config(e.to_string()))?;
        usb_config.serial = Some(serial_num);
    }

    let connector = yubihsm::Connector::from(UsbConnector::create(&usb_config));
    let credentials = Credentials::from_password(config.hsm.auth_key_id, password.as_bytes());
    Ok(Client::open(connector, credentials, true)?)
}

pub fn list_asymmetric_keys(client: &Client) -> Result<Vec<KeyInfo>, AppError> {
    let entries = client.list_objects(&[object::Filter::Type(object::Type::AsymmetricKey)])?;
    let mut keys = Vec::new();
    for entry in entries {
        let info = client.get_object_info(entry.object_id, entry.object_type)?;
        let algorithm = match info.algorithm {
            yubihsm::Algorithm::Asymmetric(alg) => alg,
            _ => {
                return Err(AppError::Hsm(
                    "unexpected non-asymmetric algorithm for key".to_string(),
                ))
            }
        };
        keys.push(KeyInfo {
            id: info.object_id,
            label: info.label.to_string(),
            algorithm,
        });
    }

    keys.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(keys)
}

pub fn list_keys(client: &Client) -> Result<Vec<KeyListEntry>, AppError> {
    let key_types = [
        object::Type::AsymmetricKey,
        object::Type::AuthenticationKey,
        object::Type::WrapKey,
        object::Type::HmacKey,
        object::Type::OtpAeadKey,
    ];
    let mut keys = Vec::new();

    for key_type in key_types {
        let entries = client.list_objects(&[object::Filter::Type(key_type)])?;
        for entry in entries {
            let info = client.get_object_info(entry.object_id, entry.object_type)?;
            keys.push(KeyListEntry {
                id: info.object_id,
                label: info.label.to_string(),
                object_type: info.object_type,
                algorithm: info.algorithm,
            });
        }
    }

    keys.sort_by(|a, b| a.id.cmp(&b.id).then_with(|| a.object_type.cmp(&b.object_type)));
    Ok(keys)
}

pub fn get_public_key(
    client: &Client,
    key_id: u16,
) -> Result<yubihsm::asymmetric::PublicKey, AppError> {
    Ok(client.get_public_key(key_id)?)
}

pub fn get_key_info(client: &Client, key_id: u16) -> Result<KeyInfo, AppError> {
    let info = client.get_object_info(key_id, object::Type::AsymmetricKey)?;
    let algorithm = match info.algorithm {
        yubihsm::Algorithm::Asymmetric(alg) => alg,
        _ => {
            return Err(AppError::Hsm(
                "unexpected non-asymmetric algorithm for key".to_string(),
            ))
        }
    };
    Ok(KeyInfo {
        id: info.object_id,
        label: info.label.to_string(),
        algorithm,
    })
}

pub fn generate_asymmetric_key(
    client: &Client,
    label: &str,
    algorithm: Algorithm,
    domains: Domain,
) -> Result<KeyInfo, AppError> {
    let label = object::Label::from_bytes(label.as_bytes())
        .map_err(|e| AppError::Usage(e.to_string()))?;
    let capabilities = capabilities_for_algorithm(algorithm);

    let key_id = client.generate_asymmetric_key(0, label, domains, capabilities, algorithm)?;
    get_key_info(client, key_id)
}

pub fn find_wrap_key_by_label(client: &Client, label: &str) -> Result<Option<u16>, AppError> {
    let entries = client.list_objects(&[object::Filter::Type(object::Type::WrapKey)])?;
    for entry in entries {
        let info = client.get_object_info(entry.object_id, entry.object_type)?;
        if info.label.to_string() == label {
            return Ok(Some(info.object_id));
        }
    }
    Ok(None)
}

pub fn auth_key_domains(client: &Client, auth_key_id: u16) -> Result<Domain, AppError> {
    let info = client.get_object_info(auth_key_id, object::Type::AuthenticationKey)?;
    Ok(info.domains)
}

pub fn generate_wrap_key(
    client: &Client,
    label: &str,
    domains: Domain,
) -> Result<u16, AppError> {
    let label = object::Label::from_bytes(label.as_bytes())
        .map_err(|e| AppError::Usage(e.to_string()))?;
    let capabilities = Capability::WRAP_DATA | Capability::UNWRAP_DATA;
    let delegated_capabilities = capabilities;
    let algorithm = wrap::Algorithm::Aes256Ccm;

    let key_id = client.generate_wrap_key(
        0,
        label,
        domains,
        capabilities,
        delegated_capabilities,
        algorithm,
    )?;
    Ok(key_id)
}

pub fn wrap_data(
    client: &Client,
    wrap_key_id: u16,
    plaintext: &[u8],
) -> Result<wrap::Message, AppError> {
    Ok(client.wrap_data(wrap_key_id, plaintext.to_vec())?)
}

pub fn unwrap_data(
    client: &Client,
    wrap_key_id: u16,
    message: wrap::Message,
) -> Result<Vec<u8>, AppError> {
    Ok(client.unwrap_data(wrap_key_id, message)?)
}

pub fn delete_asymmetric_key(client: &Client, key_id: u16) -> Result<(), AppError> {
    client.delete_object(key_id, object::Type::AsymmetricKey)?;
    Ok(())
}

pub fn find_asymmetric_key(client: &Client, id_or_label: &str) -> Result<KeyInfo, AppError> {
    if let Ok(id) = id_or_label.parse::<u16>() {
        return get_key_info(client, id);
    }

    let keys = list_asymmetric_keys(client)?;
    let matches: Vec<KeyInfo> = keys
        .into_iter()
        .filter(|key| key.label == id_or_label)
        .collect();

    match matches.len() {
        0 => Err(AppError::Usage(format!(
            "no key found with label '{}'",
            id_or_label
        ))),
        1 => Ok(matches[0].clone()),
        _ => Err(AppError::Usage(format!(
            "multiple keys found with label '{}'",
            id_or_label
        ))),
    }
}

pub fn sign_ecdsa_der(
    client: &Client,
    key_id: u16,
    algorithm: Algorithm,
    tbs: &[u8],
) -> Result<Vec<u8>, AppError> {
    let digest = match algorithm {
        Algorithm::EcP256 => Sha256::digest(tbs).to_vec(),
        Algorithm::EcP384 => Sha384::digest(tbs).to_vec(),
        _ => {
            return Err(AppError::Usage(
                "unsupported CA key algorithm for signing".to_string(),
            ))
        }
    };

    let raw_sig = client.sign_ecdsa_prehash_raw(key_id, digest)?;
    raw_ecdsa_to_der(&raw_sig)
}

pub fn parse_algorithm(input: &str) -> Result<Algorithm, AppError> {
    match input {
        "ecp256" => Ok(Algorithm::EcP256),
        "ecp384" => Ok(Algorithm::EcP384),
        "rsa2048" => Ok(Algorithm::Rsa2048),
        "rsa3072" => Ok(Algorithm::Rsa3072),
        "rsa4096" => Ok(Algorithm::Rsa4096),
        "ed25519" => Ok(Algorithm::Ed25519),
        _ => Err(AppError::Usage(format!(
            "unsupported algorithm '{}'; try ecp256",
            input
        ))),
    }
}

pub fn algorithm_name(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::EcP256 => "ecp256",
        Algorithm::EcP384 => "ecp384",
        Algorithm::Rsa2048 => "rsa2048",
        Algorithm::Rsa3072 => "rsa3072",
        Algorithm::Rsa4096 => "rsa4096",
        Algorithm::Ed25519 => "ed25519",
        Algorithm::EcP224 => "ecp224",
        Algorithm::EcP521 => "ecp521",
        Algorithm::EcK256 => "eck256",
        Algorithm::EcBp256 => "ecbp256",
        Algorithm::EcBp384 => "ecbp384",
        Algorithm::EcBp512 => "ecbp512",
    }
}

pub fn algorithm_display(algorithm: HsmAlgorithm) -> String {
    match algorithm {
        HsmAlgorithm::Asymmetric(alg) => algorithm_name(alg).to_string(),
        HsmAlgorithm::Authentication(authentication::Algorithm::YubicoAes) => {
            "yubico-aes".to_string()
        }
        HsmAlgorithm::Wrap(wrap::Algorithm::Aes128Ccm) => "aes128-ccm".to_string(),
        HsmAlgorithm::Wrap(wrap::Algorithm::Aes192Ccm) => "aes192-ccm".to_string(),
        HsmAlgorithm::Wrap(wrap::Algorithm::Aes256Ccm) => "aes256-ccm".to_string(),
        HsmAlgorithm::Hmac(hmac::Algorithm::Sha1) => "hmac-sha1".to_string(),
        HsmAlgorithm::Hmac(hmac::Algorithm::Sha256) => "hmac-sha256".to_string(),
        HsmAlgorithm::Hmac(hmac::Algorithm::Sha384) => "hmac-sha384".to_string(),
        HsmAlgorithm::Hmac(hmac::Algorithm::Sha512) => "hmac-sha512".to_string(),
        HsmAlgorithm::YubicoOtp(otp::Algorithm::Aes128) => "otp-aes128".to_string(),
        HsmAlgorithm::YubicoOtp(otp::Algorithm::Aes192) => "otp-aes192".to_string(),
        HsmAlgorithm::YubicoOtp(otp::Algorithm::Aes256) => "otp-aes256".to_string(),
        other => format!("{:?}", other),
    }
}

pub fn object_type_name(object_type: object::Type) -> &'static str {
    match object_type {
        object::Type::AuthenticationKey => "authentication-key",
        object::Type::AsymmetricKey => "asymmetric-key",
        object::Type::WrapKey => "wrap-key",
        object::Type::HmacKey => "hmac-key",
        object::Type::OtpAeadKey => "otp-aead-key",
        object::Type::Opaque => "opaque",
        object::Type::Template => "template",
    }
}

fn capabilities_for_algorithm(algorithm: Algorithm) -> Capability {
    match algorithm {
        Algorithm::Ed25519 => Capability::SIGN_EDDSA,
        Algorithm::Rsa2048 | Algorithm::Rsa3072 | Algorithm::Rsa4096 => Capability::SIGN_PKCS,
        _ => Capability::SIGN_ECDSA,
    }
}

fn raw_ecdsa_to_der(raw: &[u8]) -> Result<Vec<u8>, AppError> {
    if raw.len() % 2 != 0 {
        return Err(AppError::X509("invalid ECDSA signature length".to_string()));
    }

    let n = raw.len() / 2;
    let (r, s) = raw.split_at(n);
    let r_enc = encode_der_integer(r);
    let s_enc = encode_der_integer(s);

    let mut seq = Vec::new();
    seq.extend_from_slice(&[0x02, r_enc.len() as u8]);
    seq.extend_from_slice(&r_enc);
    seq.extend_from_slice(&[0x02, s_enc.len() as u8]);
    seq.extend_from_slice(&s_enc);

    let mut out = Vec::new();
    out.push(0x30);
    out.push(seq.len() as u8);
    out.extend_from_slice(&seq);
    Ok(out)
}

fn encode_der_integer(input: &[u8]) -> Vec<u8> {
    let mut bytes = input;
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes = &bytes[1..];
    }

    let mut out = Vec::new();
    if bytes[0] & 0x80 != 0 {
        out.push(0x00);
    }
    out.extend_from_slice(bytes);
    out
}
