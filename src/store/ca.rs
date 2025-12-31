use std::fs;
use std::path::{Path, PathBuf};

use const_oid::db::rfc4519::{COMMON_NAME, ORGANIZATIONAL_UNIT_NAME};
use der::{Decode, DecodePem, Tagged};
use serde::{Deserialize, Serialize};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::name::Name;
use x509_cert::Certificate;

use crate::app::error::AppError;

#[derive(Debug, Serialize, Deserialize)]
pub struct CaConfig {
    pub version: u8,
    pub ca: CaSection,
    pub hsm: CaHsmSection,
    pub crypto: CaCryptoSection,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CaSection {
    pub short_name: String,
    pub common_name: String,
    pub organizational_unit: String,
    pub validity_days: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CaHsmSection {
    pub key_id: u16,
    pub key_label: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CaCryptoSection {
    pub signature: String,
}

pub struct CaEntry {
    pub short_name: String,
    pub config: Option<CaConfig>,
    pub cert: Option<Certificate>,
}

pub struct CaRow {
    pub short_name: String,
    pub expires: String,
    pub common_name: String,
    pub organizational_unit: String,
    pub key_id: String,
    pub is_default: bool,
    pub status: String,
}

pub fn ca_dir(data_dir: &Path, short_name: &str) -> PathBuf {
    data_dir.join("ca").join(short_name)
}

pub fn ca_tls_dir(ca_dir: &Path) -> PathBuf {
    ca_dir.join("tls")
}

pub fn ca_config_path(ca_dir: &Path) -> PathBuf {
    ca_dir.join("config.toml")
}

pub fn ca_cert_path(ca_dir: &Path) -> PathBuf {
    ca_dir.join("ca.crt")
}

pub fn write_ca_config(path: &Path, config: &CaConfig) -> Result<(), AppError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let contents = toml::to_string_pretty(config)?;
    write_atomic(path, contents.as_bytes())
}

pub fn read_ca_config(path: &Path) -> Result<CaConfig, AppError> {
    let contents = fs::read_to_string(path)?;
    Ok(toml::from_str(&contents)?)
}

pub fn read_ca_cert(path: &Path) -> Result<Certificate, AppError> {
    let bytes = fs::read(path)?;
    if bytes.starts_with(b"-----BEGIN") {
        Ok(Certificate::from_pem(bytes)?)
    } else {
        Ok(Certificate::from_der(&bytes)?)
    }
}

pub fn list_ca_entries(data_dir: &Path) -> Result<Vec<CaEntry>, AppError> {
    let ca_root = data_dir.join("ca");
    if !ca_root.exists() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    for entry in fs::read_dir(ca_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }

        let short_name = entry.file_name().to_string_lossy().to_string();
        let dir = entry.path();
        let config_path = ca_config_path(&dir);
        let cert_path = ca_cert_path(&dir);

        let config = match read_ca_config(&config_path) {
            Ok(config) => Some(config),
            Err(_) => None,
        };

        let cert = match read_ca_cert(&cert_path) {
            Ok(cert) => Some(cert),
            Err(_) => None,
        };

        entries.push(CaEntry {
            short_name,
            config,
            cert,
        });
    }

    entries.sort_by(|a, b| a.short_name.cmp(&b.short_name));
    Ok(entries)
}

pub fn format_ca_entry(entry: CaEntry, default_ca: Option<&str>) -> Result<CaRow, AppError> {
    let mut status = "ok".to_string();
    let mut common_name = "-".to_string();
    let mut organizational_unit = "-".to_string();
    let mut expires = "-".to_string();
    let mut key_id = "-".to_string();

    if entry.config.is_none() {
        status = "missing config".to_string();
    }

    if entry.cert.is_none() {
        status = "missing cert".to_string();
    }

    if let Some(config) = &entry.config {
        key_id = config.hsm.key_id.to_string();
    }

    if let Some(cert) = &entry.cert {
        let subject = &cert.tbs_certificate.subject;
        if let Some(value) = find_attr_value(subject, COMMON_NAME) {
            common_name = value;
        }
        if let Some(value) = find_attr_value(subject, ORGANIZATIONAL_UNIT_NAME) {
            organizational_unit = value;
        }

        expires = format_time(&cert.tbs_certificate.validity.not_after)?;
    }

    let short_name = entry.short_name;
    let is_default = default_ca == Some(short_name.as_str());
    Ok(CaRow {
        short_name,
        expires,
        common_name,
        organizational_unit,
        key_id,
        is_default,
        status,
    })
}

pub fn print_ca_table(rows: &[CaRow]) {
    let headers = ["CA", "Default", "Expires", "CN", "OU", "Key", "Status"];
    let mut widths = [
        headers[0].len(),
        headers[1].len(),
        headers[2].len(),
        headers[3].len(),
        headers[4].len(),
        headers[5].len(),
        headers[6].len(),
    ];

    for row in rows {
        widths[0] = widths[0].max(row.short_name.len());
        widths[1] = widths[1].max(3);
        widths[2] = widths[2].max(row.expires.len());
        widths[3] = widths[3].max(row.common_name.len());
        widths[4] = widths[4].max(row.organizational_unit.len());
        widths[5] = widths[5].max(row.key_id.len());
        widths[6] = widths[6].max(row.status.len());
    }

    println!(
        "{:<caw$}  {:<dfw$}  {:<exw$}  {:<cnw$}  {:<ouw$}  {:<kw$}  {:<sw$}",
        headers[0],
        headers[1],
        headers[2],
        headers[3],
        headers[4],
        headers[5],
        headers[6],
        caw = widths[0],
        dfw = widths[1],
        exw = widths[2],
        cnw = widths[3],
        ouw = widths[4],
        kw = widths[5],
        sw = widths[6]
    );

    for row in rows {
        let default_flag = if row.is_default { "yes" } else { "-" };
        println!(
            "{:<caw$}  {:<dfw$}  {:<exw$}  {:<cnw$}  {:<ouw$}  {:<kw$}  {:<sw$}",
            row.short_name,
            default_flag,
            row.expires,
            row.common_name,
            row.organizational_unit,
            row.key_id,
            row.status,
            caw = widths[0],
            dfw = widths[1],
            exw = widths[2],
            cnw = widths[3],
            ouw = widths[4],
            kw = widths[5],
            sw = widths[6]
        );
    }
}

pub fn key_is_referenced(data_dir: &Path, key_id: u16) -> Result<bool, AppError> {
    let entries = list_ca_entries(data_dir)?;
    for entry in entries {
        if let Some(config) = entry.config {
            if config.hsm.key_id == key_id {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn write_atomic(path: &Path, contents: &[u8]) -> Result<(), AppError> {
    let parent = path
        .parent()
        .ok_or_else(|| AppError::Config("invalid path".to_string()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| AppError::Config("invalid path".to_string()))?
        .to_string_lossy();

    let tmp_path = parent.join(format!(".{}.tmp", file_name));
    fs::write(&tmp_path, contents)?;
    fs::rename(tmp_path, path)?;
    Ok(())
}

fn find_attr_value(name: &Name, oid: const_oid::ObjectIdentifier) -> Option<String> {
    for rdn in &name.0 {
        for attr in rdn.0.iter() {
            if attr.oid == oid {
                if let Some(value) = attribute_to_string(attr) {
                    return Some(value);
                }
            }
        }
    }
    None
}

fn attribute_to_string(attr: &AttributeTypeAndValue) -> Option<String> {
    use der::asn1::{Ia5StringRef, PrintableStringRef, TeletexStringRef, Utf8StringRef};
    use der::Tag;

    match attr.value.tag() {
        Tag::PrintableString => PrintableStringRef::try_from(&attr.value)
            .ok()
            .map(|s| s.as_str().to_string()),
        Tag::Utf8String => Utf8StringRef::try_from(&attr.value)
            .ok()
            .map(|s| s.as_str().to_string()),
        Tag::Ia5String => Ia5StringRef::try_from(&attr.value)
            .ok()
            .map(|s| s.as_str().to_string()),
        Tag::TeletexString => TeletexStringRef::try_from(&attr.value)
            .ok()
            .map(|s| s.as_str().to_string()),
        _ => None,
    }
}

pub fn format_time(time: &x509_cert::time::Time) -> Result<String, AppError> {
    let system_time = time.to_system_time();
    let dt = time::OffsetDateTime::from(system_time);
    let formatted = dt
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| AppError::X509(e.to_string()))?;
    Ok(formatted)
}
