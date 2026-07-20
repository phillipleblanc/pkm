use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "pkm", version, about = "PKI Manager for YubiHSM2")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize configuration and keyring entry
    Init,

    /// Manage keys on the HSM
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },

    /// Manage certificate authorities
    Ca {
        #[command(subcommand)]
        command: CaCommand,
    },

    /// Manage issued TLS certs
    Tls {
        #[command(subcommand)]
        command: TlsCommand,
    },
}

#[derive(Subcommand)]
pub enum KeysCommand {
    /// List keys
    List {
        #[arg(long = "all-capabilities")]
        all_capabilities: bool,
    },

    /// Create a new asymmetric key
    Add {
        label: String,

        #[arg(long, default_value = "ecp256")]
        algorithm: String,
    },

    /// Remove an asymmetric key by id or label
    Remove {
        id_or_label: String,

        #[arg(long)]
        yes: bool,

        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum CaCommand {
    /// Initialize a root CA
    Init {
        ca_short_name: String,

        #[arg(long = "key")]
        key: String,

        #[arg(long = "common-name")]
        common_name: String,

        #[arg(long = "organizational-unit")]
        organizational_unit: String,
    },

    /// List configured CAs
    List,

    /// Set the default CA for TLS operations
    Default {
        ca_short_name: String,
    },

    /// Export the CA certificate
    Export {
        #[arg(long = "ca")]
        ca: Option<String>,
    },

    /// Sign a CSR as a subordinate (intermediate) CA certificate
    SignCsr {
        #[arg(long = "ca")]
        ca: Option<String>,

        /// Path to the CSR (PEM or DER)
        #[arg(long)]
        csr: PathBuf,

        /// Output path for the signed certificate (PEM)
        #[arg(long)]
        out: PathBuf,

        /// Validity in days (clamped to the issuing CA's expiry)
        #[arg(long, default_value_t = 3650)]
        days: u32,

        /// BasicConstraints pathLenConstraint (0 = may only issue end-entity certs)
        #[arg(long = "path-len", default_value_t = 0)]
        path_len: u8,
    },

    /// External subcommand handler for `pkm ca <name> ...`
    #[command(external_subcommand)]
    External(Vec<String>),
}

#[derive(Subcommand)]
pub enum TlsCommand {
    /// Issue a TLS certificate
    Add {
        #[arg(long = "ca")]
        ca: Option<String>,

        #[command(flatten)]
        args: TlsAddArgs,
    },

    /// Export a TLS certificate
    Export {
        #[arg(long = "ca")]
        ca: Option<String>,

        #[command(flatten)]
        args: TlsExportArgs,
    },

    /// List issued TLS certificates
    List {
        #[arg(long = "ca")]
        ca: Option<String>,
    },
}

#[derive(Parser, Debug)]
pub struct TlsAddArgs {
    pub name: String,

    #[arg(long)]
    pub client: bool,

    #[arg(long)]
    pub server: bool,

    #[arg(long = "host")]
    pub hosts: Vec<String>,
}

#[derive(Parser, Debug)]
pub struct TlsExportArgs {
    pub name: String,

    #[arg(long, value_enum, default_value_t = TlsExportFormat::Pkcs12)]
    pub format: TlsExportFormat,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum TlsExportFormat {
    Pkcs12,
    Split,
}
