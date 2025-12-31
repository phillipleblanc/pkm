use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use base64::{engine::general_purpose, Engine as _};
use yubihsm::wrap;

use crate::app::error::AppError;

const WRAPPED_KEY_HEADER: &str = "-----BEGIN PKM WRAPPED KEY-----";
const WRAPPED_KEY_FOOTER: &str = "-----END PKM WRAPPED KEY-----";

pub fn is_wrapped_key(contents: &[u8]) -> bool {
    contents.starts_with(WRAPPED_KEY_HEADER.as_bytes())
}

pub fn write_wrapped_key(path: &Path, message: &wrap::Message) -> Result<(), AppError> {
    let text = format_wrapped_key(message)?;
    write_sensitive_bytes(path, text.as_bytes())
}

pub fn read_wrapped_key_bytes(contents: &[u8]) -> Result<wrap::Message, AppError> {
    let text = std::str::from_utf8(contents)
        .map_err(|_| AppError::Usage("wrapped key is not valid UTF-8".to_string()))?;
    decode_wrapped_key(text)
}

fn format_wrapped_key(message: &wrap::Message) -> Result<String, AppError> {
    let encoded = general_purpose::STANDARD.encode(message.clone().into_vec());
    let mut out = String::new();
    out.push_str(WRAPPED_KEY_HEADER);
    out.push('\n');
    for chunk in encoded.as_bytes().chunks(64) {
        let chunk = std::str::from_utf8(chunk)
            .map_err(|_| AppError::Usage("wrapped key encoding failure".to_string()))?;
        out.push_str(chunk);
        out.push('\n');
    }
    out.push_str(WRAPPED_KEY_FOOTER);
    out.push('\n');
    Ok(out)
}

fn decode_wrapped_key(text: &str) -> Result<wrap::Message, AppError> {
    let mut lines = text.lines();
    let header = lines
        .next()
        .ok_or_else(|| AppError::Usage("wrapped key is empty".to_string()))?;
    if header.trim() != WRAPPED_KEY_HEADER {
        return Err(AppError::Usage(
            "wrapped key has an invalid header".to_string(),
        ));
    }

    let mut data = String::new();
    let mut footer_found = false;
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == WRAPPED_KEY_FOOTER {
            footer_found = true;
            break;
        }
        data.push_str(line);
    }

    if !footer_found {
        return Err(AppError::Usage(
            "wrapped key has an invalid footer".to_string(),
        ));
    }

    let decoded = general_purpose::STANDARD
        .decode(data.as_bytes())
        .map_err(|e| AppError::Usage(format!("invalid wrapped key data: {e}")))?;
    wrap::Message::from_vec(decoded)
        .map_err(|e| AppError::Usage(format!("invalid wrapped key message: {e}")))
}

fn write_sensitive_bytes(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    Ok(())
}
