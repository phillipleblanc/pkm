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

# Export CA certificate (defaults to current CA)
pkm ca export

# Issue a TLS certificate
pkm tls add server1 --server --host my-server.com --host 10.0.0.10

# Export as PKCS#12 (default)
pkm tls export server1

# Export as split .crt/.pem
pkm tls export server1 --format split

# List leaf certs
pkm tls list
```

## Subordinate (intermediate) CAs

`pkm ca sign-csr` signs an external CSR with an HSM-backed CA, producing a
subordinate CA certificate. The CSR self-signature is verified before signing;
only ECDSA P-256 / SHA-256 CSRs are accepted. Requested validity is clamped to
the issuing CA's expiry.

```bash
# Generate the subordinate key + CSR (key stays wherever you generate it)
openssl ecparam -genkey -name prime256v1 -noout -out subca.key
openssl req -new -key subca.key -out subca.csr \
  -subj "/OU=YubiHSM2/CN=My Issuing CA"

# Sign it with the HSM-backed root (pathLenConstraint defaults to 0:
# the subordinate may only issue end-entity certificates)
pkm ca sign-csr --ca home --csr subca.csr --out subca.crt

# Longer chain of intermediates, if ever needed:
pkm ca sign-csr --ca home --csr subca.csr --out subca.crt --path-len 1
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
