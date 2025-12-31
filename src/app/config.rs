use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::error::AppError;
use super::paths;

#[derive(Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub version: u8,
    pub hsm: HsmConfig,
    pub keyring: KeyringConfig,
    #[serde(default)]
    pub current_ca: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HsmConfig {
    pub auth_key_id: u16,
    pub serial: Option<u32>,
    #[serde(default)]
    pub wrap_key_id: Option<u16>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyringConfig {
    pub service: String,
    pub username: String,
}

impl AppConfig {
    pub fn keyring_entry(&self) -> Result<keyring::Entry, AppError> {
        Ok(keyring::Entry::new(&self.keyring.service, &self.keyring.username)?)
    }
}

pub fn load_config() -> Result<AppConfig, AppError> {
    let path = paths::config_path()?;
    if !path.exists() {
        return Err(AppError::NotConfigured);
    }

    let contents = fs::read_to_string(path)?;
    let config = toml::from_str(&contents)?;
    Ok(config)
}

pub fn save_config(config: &AppConfig) -> Result<(), AppError> {
    let path = paths::config_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let contents = toml::to_string_pretty(config)?;
    write_atomic(&path, contents.as_bytes())
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
