# pkm

PKI Manager (pkm) is a CLI for managing a YubiHSM2-backed CA and issuing TLS leaf
certificates. It stores CA keys on the HSM and wraps leaf private keys at rest using an HSM wrap key.

## Features

- Initialize config and keyring storage for the HSM auth key
- Create CAs and issue leaf TLS certificates
- Wrap leaf private keys with the HSM and export PKCS#12 bundles
- List CAs and leaf certificates (capabilities, SANs, expiration)
- Choose a default CA via `--ca`, `PKM_CA`, or `current_ca` in config

## Requirements

- Rust toolchain (edition 2024)
- YubiHSM2 with USB access
- `openssl` in PATH (for PKCS#12 export)
- libusb (for the yubihsm USB connector)

## Install From Source

```bash
git clone https://github.com/phillipleblanc/pkm.git
cd pkm
cargo build --release
```

The binary will be at `target/release/pkm`. You can also install it into your Cargo bin dir:

```bash
cargo install --path .
```

## Quick Start

```bash
pkm init

# Create a CA
pkm ca init home --key <hsm-key-id-or-label> \
  --common-name "HomeLab Root CA" \
  --organizational-unit "HomeLab"

# Set default CA (optional)
pkm ca default home

# Issue a TLS certificate
pkm tls add server1 --server --host my-server.com --host 10.0.0.10

# Export as PKCS#12
pkm tls export server1

# List leaf certs
pkm tls list
```

## Configuration

Config lives at `$XDG_CONFIG_HOME/pkm/config.toml` (fallback `~/.config/pkm/config.toml`).
You can set a default CA:

```toml
current_ca = "home"

[hsm]
auth_key_id = 1
```

`pkm` will also honor `PKM_CA` as a default CA override.
