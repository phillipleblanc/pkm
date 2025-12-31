use std::env;
use std::path::PathBuf;

use directories::BaseDirs;

use super::error::AppError;

pub fn config_path() -> Result<PathBuf, AppError> {
    let base = if let Some(dir) = env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(dir)
    } else {
        let home = home_dir()?;
        home.join(".config")
    };

    Ok(base.join("pkm").join("config.toml"))
}

pub fn data_dir() -> Result<PathBuf, AppError> {
    let base = if let Some(dir) = env::var_os("XDG_DATA_HOME") {
        PathBuf::from(dir)
    } else {
        let home = home_dir()?;
        home.join(".local").join("share")
    };

    Ok(base.join("pkm"))
}

fn home_dir() -> Result<PathBuf, AppError> {
    BaseDirs::new()
        .map(|dirs| dirs.home_dir().to_path_buf())
        .ok_or_else(|| AppError::Config("unable to determine home directory".to_string()))
}
