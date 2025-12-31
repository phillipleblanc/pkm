pub mod config;
pub mod error;
pub mod paths;

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Parser;
use const_oid::db::rfc5280::{ID_KP_CLIENT_AUTH, ID_KP_SERVER_AUTH};
use const_oid::AssociatedOid;
use der::Decode;
use rand_core::{OsRng, RngCore};
use x509_cert::ext::pkix::{ExtendedKeyUsage, SubjectAltName};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::Certificate;
use yubihsm::{object, Client};

use crate::cli::{CaCommand, Cli, Commands, KeysCommand, TlsAddArgs, TlsCommand, TlsExportArgs};
use crate::{hsm, pki, store};
use config::{AppConfig, HsmConfig, KeyringConfig};
use error::AppError;

pub fn run(cli: Cli) -> Result<(), AppError> {
    match cli.command {
        Commands::Init => init_config(),
        Commands::Keys { command } => handle_keys(command),
        Commands::Ca { command } => handle_ca(command),
        Commands::Tls { command } => handle_tls(command),
    }
}

pub fn print_error_and_exit(err: AppError) -> ! {
    eprintln!("{}", err);
    std::process::exit(err.exit_code());
}

fn init_config() -> Result<(), AppError> {
    let path = paths::config_path()?;
    if path.exists() {
        return Err(AppError::Usage(format!(
            "config already exists at {}",
            path.display()
        )));
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let auth_key_id = prompt_auth_key_id()?;
    let password = rpassword::prompt_password("AuthKey password: ")?;

    let service = "pkm".to_string();
    let username = format!("yubihsm-authkey-{}", auth_key_id);
    let entry = keyring::Entry::new(&service, &username)?;
    entry.set_password(&password)?;

    let config = AppConfig {
        version: 1,
        hsm: HsmConfig {
            auth_key_id,
            serial: None,
            wrap_key_id: None,
        },
        keyring: KeyringConfig { service, username },
        current_ca: None,
    };

    let _client = hsm::connect_usb(&config, &password)?;

    config::save_config(&config)?;

    println!("pkm initialized");
    Ok(())
}

fn handle_keys(cmd: KeysCommand) -> Result<(), AppError> {
    let config = config::load_config()?;
    let password = config.keyring_entry()?.get_password()?;
    let client = hsm::connect_usb(&config, &password)?;

    match cmd {
        KeysCommand::List => {
            let keys = hsm::list_asymmetric_keys(&client)?;
            print_keys_table(&keys);
            Ok(())
        }
        KeysCommand::Add { label, algorithm } => {
            let algo = hsm::parse_algorithm(&algorithm)?;
            let key = hsm::generate_asymmetric_key(&client, &label, algo)?;
            println!(
                "created key {} (label: {}, algorithm: {})",
                key.id,
                key.label,
                hsm::algorithm_name(key.algorithm)
            );
            Ok(())
        }
        KeysCommand::Remove {
            id_or_label,
            yes,
            force,
        } => {
            let key = hsm::find_asymmetric_key(&client, &id_or_label)?;
            if !force {
                let referenced = store::ca::key_is_referenced(&paths::data_dir()?, key.id)?;
                if referenced {
                    return Err(AppError::Usage(format!(
                        "key {} is referenced by a CA config; re-run with --force",
                        key.id
                    )));
                }
            }

            if !yes && !prompt_yes_no(&format!(
                "Delete key {} (label: {})?",
                key.id, key.label
            ))? {
                println!("aborted");
                return Ok(());
            }

            hsm::delete_asymmetric_key(&client, key.id)?;
            println!("deleted key {}", key.id);
            Ok(())
        }
    }
}

fn handle_ca(cmd: CaCommand) -> Result<(), AppError> {
    match cmd {
        CaCommand::Init {
            ca_short_name,
            key,
            common_name,
            organizational_unit,
        } => ca_init(&ca_short_name, &key, &common_name, &organizational_unit),
        CaCommand::List => ca_list(),
        CaCommand::Default { ca_short_name } => ca_set_default(&ca_short_name),
        CaCommand::External(args) => ca_external(args),
    }
}

fn handle_tls(cmd: TlsCommand) -> Result<(), AppError> {
    match cmd {
        TlsCommand::Add { ca, args } => {
            let ca_short_name = resolve_ca_short_name(ca)?;
            ca_tls_add(&ca_short_name, args)
        }
        TlsCommand::Export { ca, args } => {
            let ca_short_name = resolve_ca_short_name(ca)?;
            ca_tls_export(&ca_short_name, args)
        }
        TlsCommand::List { ca } => {
            let ca_short_name = resolve_ca_short_name(ca)?;
            tls_list(&ca_short_name)
        }
    }
}

fn ca_external(args: Vec<String>) -> Result<(), AppError> {
    if args.len() < 3 {
        return Err(AppError::Usage(
            "expected: pkm ca <name> tls add|export <name> [flags]".to_string(),
        ));
    }

    let ca_short_name = &args[0];
    let section = &args[1];
    let action = &args[2];
    if section != "tls" {
        return Err(AppError::Usage(
            "expected: pkm ca <name> tls add|export <name> [flags]".to_string(),
        ));
    }

    match action.as_str() {
        "add" => {
            let mut argv = vec!["tls-add".to_string()];
            argv.extend(args[3..].iter().cloned());
            let tls_args =
                TlsAddArgs::try_parse_from(argv).map_err(|e| AppError::Usage(e.to_string()))?;
            ca_tls_add(ca_short_name, tls_args)
        }
        "export" => {
            let mut argv = vec!["tls-export".to_string()];
            argv.extend(args[3..].iter().cloned());
            let tls_args =
                TlsExportArgs::try_parse_from(argv).map_err(|e| AppError::Usage(e.to_string()))?;
            ca_tls_export(ca_short_name, tls_args)
        }
        _ => Err(AppError::Usage(
            "expected: pkm ca <name> tls add|export <name> [flags]".to_string(),
        )),
    }
}

fn resolve_ca_short_name(cli_ca: Option<String>) -> Result<String, AppError> {
    if let Some(ca) = cli_ca {
        let trimmed = ca.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    if let Ok(ca) = env::var("PKM_CA") {
        let trimmed = ca.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    match config::load_config() {
        Ok(config) => {
            if let Some(ca) = config.current_ca.as_ref() {
                let trimmed = ca.trim();
                if !trimmed.is_empty() {
                    return Ok(trimmed.to_string());
                }
            }
        }
        Err(AppError::NotConfigured) => {}
        Err(err) => return Err(err),
    }

    let entries = store::ca::list_ca_entries(&paths::data_dir()?)?;
    if entries.len() == 1 {
        return Ok(entries[0].short_name.clone());
    }

    if entries.is_empty() {
        return Err(AppError::Usage(
            "no CAs found; use --ca, set PKM_CA, or set current_ca in config".to_string(),
        ));
    }

    Err(AppError::Usage(
        "multiple CAs found; use --ca, set PKM_CA, or set current_ca in config".to_string(),
    ))
}

fn resolve_default_ca_for_list(entries: &[store::ca::CaEntry]) -> Option<String> {
    if let Ok(ca) = env::var("PKM_CA") {
        let trimmed = ca.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    if let Ok(config) = config::load_config() {
        if let Some(ca) = config.current_ca.as_ref() {
            let trimmed = ca.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }

    if entries.len() == 1 {
        return Some(entries[0].short_name.clone());
    }

    None
}

fn ca_init(
    ca_short_name: &str,
    key: &str,
    common_name: &str,
    organizational_unit: &str,
) -> Result<(), AppError> {
    let config = config::load_config()?;
    let password = config.keyring_entry()?.get_password()?;
    let client = hsm::connect_usb(&config, &password)?;

    let ca_dir = store::ca::ca_dir(&paths::data_dir()?, ca_short_name);
    if ca_dir.exists() {
        return Err(AppError::Usage(format!(
            "CA directory already exists: {}",
            ca_dir.display()
        )));
    }

    let key_info = hsm::find_asymmetric_key(&client, key)?;
    let public_key = hsm::get_public_key(&client, key_info.id)?;

    let subject = pki::name_from_cn_ou(common_name, organizational_unit)?;
    let signature_alg = pki::signature_algorithm_identifier(key_info.algorithm)?;
    let validity = pki::validity_from_now_days(3650, true)?;
    let serial = pki::random_serial()?;
    let subject_spki = pki::spki_from_hsm_public_key(&public_key)?;

    let cert = pki::build_root_ca(
        subject,
        serial,
        validity,
        subject_spki,
        signature_alg.clone(),
        |tbs| hsm::sign_ecdsa_der(&client, key_info.id, key_info.algorithm, tbs),
    )?;

    fs::create_dir_all(store::ca::ca_tls_dir(&ca_dir))?;
    pki::write_cert_pem(&store::ca::ca_cert_path(&ca_dir), &cert)?;

    let ca_config = store::ca::CaConfig {
        version: 1,
        ca: store::ca::CaSection {
            short_name: ca_short_name.to_string(),
            common_name: common_name.to_string(),
            organizational_unit: organizational_unit.to_string(),
            validity_days: 3650,
        },
        hsm: store::ca::CaHsmSection {
            key_id: key_info.id,
            key_label: Some(key_info.label.clone()),
        },
        crypto: store::ca::CaCryptoSection {
            signature: pki::signature_name(key_info.algorithm).to_string(),
        },
    };

    store::ca::write_ca_config(&store::ca::ca_config_path(&ca_dir), &ca_config)?;

    println!("created CA {}", ca_short_name);
    Ok(())
}

fn ca_list() -> Result<(), AppError> {
    let data_dir = paths::data_dir()?;
    let entries = store::ca::list_ca_entries(&data_dir)?;

    if entries.is_empty() {
        println!("no CAs found");
        return Ok(());
    }

    let default_ca = resolve_default_ca_for_list(&entries);

    let mut rows = Vec::new();
    for entry in entries {
        rows.push(store::ca::format_ca_entry(entry, default_ca.as_deref())?);
    }

    store::ca::print_ca_table(&rows);
    Ok(())
}

fn ca_set_default(ca_short_name: &str) -> Result<(), AppError> {
    let data_dir = paths::data_dir()?;
    let ca_dir = store::ca::ca_dir(&data_dir, ca_short_name);
    if !ca_dir.exists() {
        return Err(AppError::Usage(format!(
            "CA directory does not exist: {}",
            ca_dir.display()
        )));
    }

    let mut config = config::load_config()?;
    config.current_ca = Some(ca_short_name.to_string());
    config::save_config(&config)?;
    println!("default CA set to {}", ca_short_name);
    Ok(())
}

fn ca_tls_add(ca_short_name: &str, args: TlsAddArgs) -> Result<(), AppError> {
    let mut config = config::load_config()?;
    let password = config.keyring_entry()?.get_password()?;
    let client = hsm::connect_usb(&config, &password)?;
    let wrap_key_id = ensure_tls_wrap_key_id(&mut config, &client)?;

    let ca_dir = store::ca::ca_dir(&paths::data_dir()?, ca_short_name);
    let ca_config_path = store::ca::ca_config_path(&ca_dir);
    let ca_cert_path = store::ca::ca_cert_path(&ca_dir);

    let ca_config = store::ca::read_ca_config(&ca_config_path)?;
    let ca_cert = store::ca::read_ca_cert(&ca_cert_path)?;

    let ca_key_info = hsm::get_key_info(&client, ca_config.hsm.key_id)?;
    let ca_subject = ca_cert.tbs_certificate.subject.clone();
    let ca_spki = ca_cert.tbs_certificate.subject_public_key_info.clone();

    let leaf_key = pki::generate_leaf_key()?;
    let leaf_spki = pki::spki_from_leaf_key(&leaf_key)?;
    let leaf_subject = pki::name_from_cn_ou(&args.name, &ca_config.ca.organizational_unit)?;

    let validity = pki::validity_from_now_days(365, false)?;
    let serial = pki::random_serial()?;
    let signature_alg = pki::signature_algorithm_identifier(ca_key_info.algorithm)?;

    let cert = pki::build_leaf_cert(
        leaf_subject,
        ca_subject,
        serial,
        validity,
        leaf_spki,
        ca_spki,
        signature_alg.clone(),
        &args,
        |tbs| hsm::sign_ecdsa_der(&client, ca_config.hsm.key_id, ca_key_info.algorithm, tbs),
    )?;

    let tls_dir = store::ca::ca_tls_dir(&ca_dir);
    fs::create_dir_all(&tls_dir)?;

    let key_path = tls_dir.join(format!("{}.pem", args.name));
    let cert_path = tls_dir.join(format!("{}.crt", args.name));

    let key_pem = pki::private_key_pem_bytes(&leaf_key)?;
    let wrapped_key = hsm::wrap_data(&client, wrap_key_id, &key_pem)?;
    pki::write_wrapped_key(&key_path, &wrapped_key)?;
    pki::write_cert_pem(&cert_path, &cert)?;

    println!("issued cert {} for CA {}", args.name, ca_short_name);
    Ok(())
}

fn ca_tls_export(ca_short_name: &str, args: TlsExportArgs) -> Result<(), AppError> {
    let mut config = config::load_config()?;
    let hsm_password = config.keyring_entry()?.get_password()?;
    let client = hsm::connect_usb(&config, &hsm_password)?;
    let wrap_key_id = ensure_tls_wrap_key_id(&mut config, &client)?;

    let ca_dir = store::ca::ca_dir(&paths::data_dir()?, ca_short_name);
    let tls_dir = store::ca::ca_tls_dir(&ca_dir);

    let key_path = tls_dir.join(format!("{}.pem", args.name));
    let cert_path = tls_dir.join(format!("{}.crt", args.name));
    let ca_cert_path = store::ca::ca_cert_path(&ca_dir);

    if !key_path.exists() {
        return Err(AppError::Usage(format!(
            "missing TLS key: {}",
            key_path.display()
        )));
    }

    if !cert_path.exists() {
        return Err(AppError::Usage(format!(
            "missing TLS cert: {}",
            cert_path.display()
        )));
    }

    if !ca_cert_path.exists() {
        return Err(AppError::Usage(format!(
            "missing CA cert: {}",
            ca_cert_path.display()
        )));
    }

    let bundle_password = rpassword::prompt_password("PKCS12 password: ")?;
    if bundle_password.is_empty() {
        return Err(AppError::Usage("password cannot be empty".to_string()));
    }

    let key_pem = read_tls_private_key_pem(&client, wrap_key_id, &key_path)?;
    let temp_key = TempKeyFile::new("pkm-tls", &key_pem)?;

    let mut output_path = env::current_dir()?;
    output_path.push(format!("{}.p12", args.name));

    let output = Command::new("openssl")
        .arg("pkcs12")
        .arg("-export")
        .arg("-inkey")
        .arg(temp_key.path())
        .arg("-in")
        .arg(&cert_path)
        .arg("-certfile")
        .arg(&ca_cert_path)
        .arg("-name")
        .arg(&args.name)
        .arg("-out")
        .arg(&output_path)
        .arg("-passout")
        .arg("env:PKM_P12_PASS")
        .env("PKM_P12_PASS", &bundle_password)
        .output()
        .map_err(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                AppError::Usage("openssl not found in PATH".to_string())
            } else {
                AppError::Io(err)
            }
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = if !stderr.trim().is_empty() {
            stderr.trim()
        } else if !stdout.trim().is_empty() {
            stdout.trim()
        } else {
            "unknown error"
        };

        return Err(AppError::Usage(format!(
            "openssl pkcs12 export failed: {}",
            detail
        )));
    }

    println!("exported {} to {}", args.name, output_path.display());
    Ok(())
}

fn tls_list(ca_short_name: &str) -> Result<(), AppError> {
    let ca_dir = store::ca::ca_dir(&paths::data_dir()?, ca_short_name);
    let tls_dir = store::ca::ca_tls_dir(&ca_dir);

    if !tls_dir.exists() {
        println!("no TLS certs found for CA {}", ca_short_name);
        return Ok(());
    }

    let mut rows = Vec::new();
    for entry in fs::read_dir(&tls_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }

        let path = entry.path();
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if ext != "crt" {
            continue;
        }

        let name = match path.file_stem().and_then(|s| s.to_str()) {
            Some(name) => name.to_string(),
            None => continue,
        };

        let cert = store::ca::read_ca_cert(&path)?;
        rows.push(format_tls_row(name, &cert)?);
    }

    if rows.is_empty() {
        println!("no TLS certs found for CA {}", ca_short_name);
        return Ok(());
    }

    rows.sort_by(|a, b| a.name.cmp(&b.name));
    print_tls_table(&rows);
    Ok(())
}

struct TlsRow {
    name: String,
    capabilities: String,
    sans: String,
    expires: String,
}

fn format_tls_row(name: String, cert: &Certificate) -> Result<TlsRow, AppError> {
    let expires = store::ca::format_time(&cert.tbs_certificate.validity.not_after)?;
    let capabilities = format_tls_capabilities(cert)?;
    let sans = format_tls_sans(cert)?;

    Ok(TlsRow {
        name,
        capabilities,
        sans,
        expires,
    })
}

fn format_tls_capabilities(cert: &Certificate) -> Result<String, AppError> {
    let mut caps = Vec::new();
    if let Some(extensions) = cert.tbs_certificate.extensions.as_ref() {
        for ext in extensions {
            if ext.extn_id == ExtendedKeyUsage::OID {
                let eku = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes())?;
                for oid in eku.0 {
                    let label = if oid == ID_KP_CLIENT_AUTH {
                        "client".to_string()
                    } else if oid == ID_KP_SERVER_AUTH {
                        "server".to_string()
                    } else {
                        oid.to_string()
                    };
                    if !caps.contains(&label) {
                        caps.push(label);
                    }
                }
            }
        }
    }

    if caps.is_empty() {
        Ok("-".to_string())
    } else {
        Ok(caps.join(","))
    }
}

fn format_tls_sans(cert: &Certificate) -> Result<String, AppError> {
    let mut sans = Vec::new();
    if let Some(extensions) = cert.tbs_certificate.extensions.as_ref() {
        for ext in extensions {
            if ext.extn_id == SubjectAltName::OID {
                let san = SubjectAltName::from_der(ext.extn_value.as_bytes())?;
                for name in san.0 {
                    if let Some(value) = format_general_name(&name) {
                        sans.push(value);
                    }
                }
            }
        }
    }

    if sans.is_empty() {
        Ok("-".to_string())
    } else {
        Ok(sans.join(","))
    }
}

fn format_general_name(name: &GeneralName) -> Option<String> {
    match name {
        GeneralName::DnsName(value) => Some(value.as_str().to_string()),
        GeneralName::IpAddress(value) => Some(format_ip_address(value.as_bytes())),
        _ => None,
    }
}

fn format_ip_address(bytes: &[u8]) -> String {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    match bytes.len() {
        4 => IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])).to_string(),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            IpAddr::V6(Ipv6Addr::from(octets)).to_string()
        }
        _ => format!("ip:{}", hex_encode(bytes)),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn print_tls_table(rows: &[TlsRow]) {
    let headers = ["Name", "Capabilities", "SANs", "Expires"];
    let mut widths = [headers[0].len(), headers[1].len(), headers[2].len(), headers[3].len()];

    for row in rows {
        widths[0] = widths[0].max(row.name.len());
        widths[1] = widths[1].max(row.capabilities.len());
        widths[2] = widths[2].max(row.sans.len());
        widths[3] = widths[3].max(row.expires.len());
    }

    println!(
        "{:<nw$}  {:<cw$}  {:<sw$}  {:<ew$}",
        headers[0],
        headers[1],
        headers[2],
        headers[3],
        nw = widths[0],
        cw = widths[1],
        sw = widths[2],
        ew = widths[3]
    );

    for row in rows {
        println!(
            "{:<nw$}  {:<cw$}  {:<sw$}  {:<ew$}",
            row.name,
            row.capabilities,
            row.sans,
            row.expires,
            nw = widths[0],
            cw = widths[1],
            sw = widths[2],
            ew = widths[3]
        );
    }
}

fn ensure_tls_wrap_key_id(config: &mut AppConfig, client: &Client) -> Result<u16, AppError> {
    if let Some(key_id) = config.hsm.wrap_key_id {
        if client
            .get_object_info(key_id, object::Type::WrapKey)
            .is_ok()
        {
            return Ok(key_id);
        }
    }

    if let Some(key_id) = hsm::find_wrap_key_by_label(client, hsm::TLS_WRAP_KEY_LABEL)? {
        config.hsm.wrap_key_id = Some(key_id);
        config::save_config(config)?;
        return Ok(key_id);
    }

    let domains = hsm::auth_key_domains(client, config.hsm.auth_key_id)?;
    let key_id = hsm::generate_wrap_key(client, hsm::TLS_WRAP_KEY_LABEL, domains)?;
    config.hsm.wrap_key_id = Some(key_id);
    config::save_config(config)?;
    Ok(key_id)
}

fn read_tls_private_key_pem(
    client: &Client,
    wrap_key_id: u16,
    key_path: &Path,
) -> Result<Vec<u8>, AppError> {
    let contents = fs::read(key_path)?;
    if pki::is_wrapped_key(&contents) {
        let message = pki::read_wrapped_key_bytes(&contents)?;
        let decrypted = hsm::unwrap_data(client, wrap_key_id, message)?;
        if decrypted.is_empty() {
            return Err(AppError::Usage("decrypted key is empty".to_string()));
        }
        return Ok(decrypted);
    }

    if !contents.starts_with(b"-----BEGIN") {
        return Err(AppError::Usage(format!(
            "unsupported TLS key format: {}",
            key_path.display()
        )));
    }

    let wrapped = hsm::wrap_data(client, wrap_key_id, &contents)?;
    pki::write_wrapped_key(key_path, &wrapped)?;
    Ok(contents)
}

struct TempKeyFile {
    path: PathBuf,
}

impl TempKeyFile {
    fn new(prefix: &str, contents: &[u8]) -> Result<Self, AppError> {
        for _ in 0..10 {
            let name = format!("{}-{}.pem", prefix, random_hex(16));
            let path = env::temp_dir().join(name);

            let mut options = OpenOptions::new();
            options.write(true).create_new(true);

            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }

            match options.open(&path) {
                Ok(mut file) => {
                    file.write_all(contents)?;
                    return Ok(Self { path });
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(AppError::Io(err)),
            }
        }

        Err(AppError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "failed to create a temporary key file",
        )))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempKeyFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn random_hex(byte_len: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = vec![0u8; byte_len];
    OsRng.fill_bytes(&mut bytes);

    let mut out = String::with_capacity(byte_len * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn prompt_auth_key_id() -> Result<u16, AppError> {
    print!("AuthKey ID [1]: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(1);
    }

    trimmed
        .parse::<u16>()
        .map_err(|_| AppError::Usage("AuthKey ID must be a u16".to_string()))
}

fn prompt_yes_no(question: &str) -> Result<bool, AppError> {
    print!("{} [y/N]: ", question);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let answer = input.trim().to_lowercase();
    Ok(answer == "y" || answer == "yes")
}

fn print_keys_table(keys: &[hsm::KeyInfo]) {
    let headers = ["ID", "Label", "Algorithm"];
    let mut widths = [headers[0].len(), headers[1].len(), headers[2].len()];

    for key in keys {
        widths[0] = widths[0].max(key.id.to_string().len());
        widths[1] = widths[1].max(key.label.len());
        widths[2] = widths[2].max(hsm::algorithm_name(key.algorithm).len());
    }

    println!(
        "{:<idw$}  {:<lw$}  {:<aw$}",
        headers[0],
        headers[1],
        headers[2],
        idw = widths[0],
        lw = widths[1],
        aw = widths[2]
    );

    for key in keys {
        println!(
            "{:<idw$}  {:<lw$}  {:<aw$}",
            key.id,
            key.label,
            hsm::algorithm_name(key.algorithm),
            idw = widths[0],
            lw = widths[1],
            aw = widths[2]
        );
    }
}
