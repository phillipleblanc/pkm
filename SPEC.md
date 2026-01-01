# PKM: YubiHSM2-backed mTLS certificate manager

* Manages **asymmetric keys on a YubiHSM2**
* Creates a **root CA cert** signed by a CA key *inside the HSM*
* Issues **mTLS leaf certs** signed by that CA key
* Talks to the HSM **directly over USB** (no `yubihsm-connector` service)

This design is based on:

* Yubico’s own note that the SDK supports a **direct USB backend** (`yhusb://…`) which avoids running an external connector (but requires **exclusive access**). ([docs.yubico.com][1])
* The community-supported **pure-Rust `yubihsm` crate** (aka `yubihsm.rs`) which provides a **USB backend using `rusb`** and shows a concrete example of connecting via `UsbConnector::default()` and authenticating with credentials. ([GitHub][2])
* The Rust **`keyring` crate** for storing the AuthKey password in the OS keychain. ([Docs.rs][3])

---

## 1) Product goals

### Non-goals (explicit)

* No production-hardening (HSM policy, audit logging, multi-admin quorum, etc.)
* No online CRL/OCSP responder implementation
* No integration with system trust stores (just file outputs)

### Primary UX goals

* One binary, self-contained: `pkm …`
* No background service: connect to HSM via **USB** using `yubihsm` crate’s USB connector backend ([Docs.rs][4])
* Works on Linux/macOS; Windows is “best effort” (USB permissions and libusb often differ)

---

## 2) Storage layout (must match user requirements)

### App data directory

* `$XDG_DATA_HOME/pkm`
* fallback: `~/.local/share/pkm`

Within it:

```
$DATA/pkm/
  ca/
    <ca-short-name>/
      ca.crt
      config.toml
      tls/
        <name>.crt
        <name>.pem    # private key for leaf (filesystem)
```

### Config directory

* `$XDG_CONFIG_HOME/pkm/config.toml`
* fallback: `~/.config/pkm/config.toml`

### Init gate

If the config file does not exist:

* any command except `pkm init` exits non-zero with:

  * “pkm is not configured yet — run `pkm init` first”

---

## 3) Dependencies (recommended Rust crates)

### CLI & ergonomics

* `clap` (derive) for command tree
* `thiserror` + `anyhow` for error reporting
* `tokio` optional (not required; USB calls can be sync)

### XDG paths

* Option A: `directories` crate (cross-platform standard dirs) ([Crates.io][5])
* Option B: `xdg` crate (XDG-focused; especially good on Linux) ([Docs.rs][6])
  **Spec requirement:** implement exactly the environment-variable behavior stated (XDG + fallback paths). Use whichever crate helps, but ensure it matches the required fallbacks.

### Keychain storage

* `keyring` crate to store/retrieve the HSM AuthKey password ([Docs.rs][3])

### YubiHSM USB access

* `yubihsm` crate (pure-Rust client) with USB backend (`rusb`) ([GitHub][2])

### X.509 construction / DER

One of these approaches:

* **Preferred (more explicit/low-magic):** RustCrypto `x509-cert` + `der` + `spki` crates for building TBSCertificate and encoding DER.
* **Alternate (higher level):** `rcgen` for keygen + cert building, but you must confirm it can use an *external signer* for the CA key; if not, fall back to `x509-cert`.

Leaf key generation can be done with:

* `p256` (for ECDSA P-256 leaf keys) or
* `ring` or `openssl` (but prefer RustCrypto)

---

## 4) HSM connection model

### Connection must be direct USB

Implementation must use `yubihsm` crate USB connector. The docs show:

* `let connector = UsbConnector::default();`
* `Client::open(connector, credentials, true)` ([Docs.rs][4])

### Exclusive access note

Direct USB mode typically means the process must have exclusive access (no other connector/client concurrently), mirroring Yubico’s own warning for the built-in USB connector backend. ([docs.yubico.com][1])

### Auth credentials

Config stores:

* `auth_key_id: u16`
* Keyring reference (how to locate secret):

  * `keyring_service: "pkm"`
  * `keyring_username: "yubihsm-authkey-<id>"` (or equivalent)

Password must **not** be stored in config or data files.

`current_ca` may be set to a CA short name to act as the default for TLS operations.

---

## 5) Configuration file formats

### `$XDG_CONFIG_HOME/pkm/config.toml`

```toml
version = 1
current_ca = "home"

[hsm]
auth_key_id = 1
# Optional: choose a particular device if multiple are present
# serial = 123456
# Optional: wrap key id used to encrypt TLS leaf keys at rest
# wrap_key_id = 2001

[keyring]
service = "pkm"
username = "yubihsm-authkey-1"
```

### `$XDG_DATA_HOME/pkm/ca/<ca-short-name>/config.toml`

```toml
version = 1

[ca]
short_name = "home"
common_name = "HomeLab Root CA"
organizational_unit = "HomeLab"
# validity in days or explicit not_after recommended; spec says 10 years
validity_days = 3650

[hsm]
# The CA key used to sign leaf certs
key_id = 1234
# Optional: store label too for display
key_label = "home-root-ca"

[crypto]
# The signature algorithm used for the CA key (derived from key algorithm)
# e.g. "ecdsa-p256-sha256"
signature = "ecdsa-p256-sha256"
```

---

## 6) Command tree & behavior (must match user’s requested UX)

### `pkm init`

**Purpose**

* Create `$XDG_CONFIG_HOME/pkm/config.toml`
* Prompt for:

  * AuthKey ID (default 1)
  * Password (hidden input)
* Store password in OS keyring; store keyring lookup info in config

**Flow**

1. Resolve config path; ensure parent dir exists.
2. Prompt for AuthKey ID (u16).
3. Prompt for password (no echo).
4. Write to keyring using:

   * service = `"pkm"`
   * username = `"yubihsm-authkey-<id>"`
5. Write config file atomically (write temp + rename).
6. Verify by opening USB connection and attempting to authenticate (optional but strongly recommended; fail init if auth fails).

**Exit codes**

* 0 success
* non-zero on keyring failure, file IO failure, or auth failure

---

### `pkm keys list`

List asymmetric keys on the device, pretty-format:

* object id
* label
* algorithm

**Implementation details**

* Query HSM for objects of type “asymmetric key”
* Display table view (column aligned)

---

### `pkm keys add <label> --algorithm <algo>`

Create a new asymmetric key on the HSM.

* Default algorithm: `ecp256`
* Supported `--algorithm` values (minimum):

  * `ecp256` (default)
  * `ecp384` (optional)
  * `rsa2048`/`rsa3072`/`rsa4096` (optional; slower)
  * (If implemented) `ed25519` (note: X.509 + Ed25519 is fine conceptually, but confirm end-to-end mTLS compatibility in your homelab stack)

**Key attributes**

* Domain: 0 (or configurable later)
* Capabilities: must include **signing** for certificate issuance
* Label: provided `<label>`
* ID allocation:

  * Either: let HSM allocate an ID (recommended)
  * Or: pick an available ID (more complexity)

**Output**

* Print newly created key id, label, algorithm

---

### `pkm keys remove`

Remove an asymmetric key.
**Spec decision:** make this either:

* `pkm keys remove <id-or-label>` (recommended for usability)
* If you insist on separate flags: `pkm keys remove --id <id>` and/or `--label <label>`

**Safety**

* Prompt “Are you sure?” unless `--yes`
* Refuse to delete if it is referenced by any CA config under `$DATA/pkm/ca/**/config.toml` unless `--force`

---

### `pkm ca default <ca-short-name>`

Set the default CA used by `pkm tls add` and `pkm tls export` when `--ca` is not provided.

* Updates `current_ca` in config.toml.
* Errors if the CA directory does not exist.

---

### `pkm ca init <ca-short-name> --key <id-or-label> --common-name <cn> --organizational-unit <ou>`

Creates:

* `$DATA/pkm/ca/<ca-short-name>/ca.crt` — **self-signed root CA cert**, valid **10 years**
* `$DATA/pkm/ca/<ca-short-name>/config.toml` — contains the CA metadata + HSM key id

**Certificate profile (Root CA)**

* Subject = Issuer

  * CN = `--common-name`
  * OU = `--organizational-unit`
* Validity

  * not_before = now - 5 minutes (clock skew tolerance)
  * not_after = now + 3650 days (10 years)
* KeyUsage: `keyCertSign`, `cRLSign`
* BasicConstraints: `CA=true`, pathLenConstraint absent or 0 (either is fine for homelab)
* SubjectKeyIdentifier + AuthorityKeyIdentifier (recommended)

**Signing**

* CA private key stays in HSM
* Build TBSCertificate in Rust, hash if required, then call HSM **sign** operation using that key.

---

### `pkm ca list`

List all CA directories under `$DATA/pkm/ca/*` and show:

* CA short name
* Expiration (not_after)
* CN, OU
* HSM key id (and label if available)

**How to parse**

* Read `<ca>/ca.crt` (X.509 parse)
* Read `<ca>/config.toml`
* If one exists but not the other → show “broken” status

---

### `pkm tls add <name> --ca <ca-short-name> --client --server --host <host>`

Creates a leaf private key (filesystem) and signed certificate (by CA key in HSM):

* `$DATA/pkm/ca/<ca-short-name>/tls/<name>.pem` (private key, HSM-wrapped)
* `$DATA/pkm/ca/<ca-short-name>/tls/<name>.crt` (certificate)

**Flags**

* `--ca <ca-short-name>` selects which CA to use.
  * If omitted, resolution order:
    1) `PKM_CA` env var
    2) `current_ca` in config.toml
    3) Only CA present in `$DATA/pkm/ca/`

* `--client` adds EKU ClientAuth
* `--server` adds EKU ServerAuth
* Both may be set
* `--host` may be specified multiple times:

  * If value parses as IP → add as IP SAN
  * Else → add as DNS SAN

**Leaf key generation**

* Generate keypair on host (default: ECDSA P-256)
* File permissions: `0600` on Unix
* Encoding: PEM

**Private key storage**

* Encrypt the PEM with the HSM using an AES-CCM wrap key labeled `pkm-tls-wrap`
* Store wrapped key as ASCII with `-----BEGIN PKM WRAPPED KEY-----` / `-----END PKM WRAPPED KEY-----`

**Leaf certificate profile**

* Subject:

  * CN = `<name>` (or optionally allow `--common-name` later)
  * OU inherit from CA or leave blank (spec: not required, but consistent is nice)
* Validity:

  * Default: 825 days (common “reasonable” lifetime) OR pick 365 days for simplicity
  * Make it configurable later; for now pick 365 days unless you prefer longer
* KeyUsage:

  * For `--server`: digitalSignature, keyEncipherment (if RSA) or just digitalSignature (ECDSA)
  * For `--client`: digitalSignature
* ExtendedKeyUsage:

  * clientAuth if `--client`
  * serverAuth if `--server`
* SubjectAltName:

  * derived from `--host` values
* AuthorityKeyIdentifier / SKI recommended

**Signing**

* Same mechanism as CA init: assemble TBSCertificate in Rust, then call HSM sign with CA key id.

---

### `pkm tls export <name> --ca <ca-short-name>`

Exports a PKCS#12 bundle for a leaf certificate into the current working directory:

* `$CWD/<name>.p12` (PKCS#12 bundle)

**Behavior**

* Prompts for a bundle password.
* Uses `<ca>/tls/<name>.pem`, `<ca>/tls/<name>.crt`, and `<ca>/ca.crt`.
* Requires `openssl` in `PATH`.
* CA selection uses the same rules as `pkm tls add`.

---

### `pkm tls list --ca <ca-short-name>`

List issued leaf TLS certificates for a CA, showing capabilities, SANs, and expiration.

* CA selection uses the same rules as `pkm tls add`.
* Capabilities are derived from Extended Key Usage (client/server).

---

## 7) Internal architecture (Rust modules)

Recommended crate layout:

* `main.rs`:

  * clap command parsing
  * calls into `app::run()`

* `app/paths.rs`:

  * resolves:

    * `config_path()`
    * `data_dir()`
  * ensures fallbacks exactly as required

* `app/config.rs`:

  * load/save config.toml
  * init guard helper:

    * `require_config_or_exit()`

* `hsm/mod.rs`:

  * `connect_usb(config) -> yubihsm::Client`
  * `list_asymmetric_keys(client) -> Vec<KeyInfo>`
  * `generate_asymmetric_key(...) -> KeyInfo`
  * `delete_object(...)`
  * `sign_with_key(key_id, msg) -> signature`

Use `yubihsm` USB connection (example pattern shown in docs). ([Docs.rs][4])

* `pki/x509.rs`:

  * functions to build:

    * root CA TBSCert
    * leaf TBSCert
  * encode DER
  * glue code:

    * `tbs_bytes -> hsm_sign -> cert_der`

* `pki/pem.rs`:

  * write private key PEM
  * write cert PEM (optional; spec says `.crt`, which can be DER or PEM—pick one and document it; I recommend PEM for convenience)

* `store/ca.rs`:

  * create/read CA directory
  * list CA directories
  * load CA config + parse cert

---

## 8) Algorithm mapping rules

Minimum required:

* HSM key algorithm `ecp256` → certificate signature algorithm `ecdsa-with-SHA256`

When HSM returns a signature:

* Ensure you output correct DER encoding for ECDSA signature (ASN.1 SEQUENCE of r,s) if needed by the x509 assembly layer.

---

## 9) Error handling & messages (UX contract)

Common errors must be human-friendly:

* Missing config → “run `pkm init` first”
* Keyring missing secret → “AuthKey password not found in keyring; re-run `pkm init`”
* USB permission error → hint about udev rules / running as correct user
* CA not found → “Unknown CA `<name>`. See `pkm ca list`.”

Exit codes:

* `0` success
* `2` misuse (bad args)
* `3` not configured
* `4` HSM connection/auth failure
* `5` filesystem/keyring failure

---

## 10) Acceptance criteria (tests / manual verification)

1. `pkm init` creates config and stores password in keyring.
2. `pkm keys add test` creates an ecp256 key and prints its id.
3. `pkm keys list` shows the new key (id/label/algo).
4. `pkm ca init home --key test --common-name "Home CA" --organizational-unit "Homelab"`

   * creates `$DATA/pkm/ca/home/ca.crt` valid ~10 years
5. `pkm ca list` shows `home` and correct expiration/CN/OU/key id
6. `pkm tls add server1 --ca home --server --host my-server.com --host 10.0.0.10`

   * produces `server1.pem` + `server1.crt`
   * SAN contains DNS + IP
   * EKU includes serverAuth
7. mTLS smoke test: your TLS stack accepts the chain using `ca.crt` as the trust anchor.

[1]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-sdk-tools-libraries.html?utm_source=chatgpt.com "YubiHSM 2 SDK Tools And Libraries"
[2]: https://github.com/iqlusioninc/yubihsm.rs?utm_source=chatgpt.com "GitHub - iqlusioninc/yubihsm.rs: Pure Rust client for YubiHSM2 devices"
[3]: https://docs.rs/keyring/latest/keyring/?utm_source=chatgpt.com "keyring - Rust - Docs.rs"
[4]: https://docs.rs/yubihsm/0.23.0 "yubihsm - Rust"
[5]: https://crates.io/crates/directories?utm_source=chatgpt.com "directories - crates.io: Rust Package Registry"
[6]: https://docs.rs/xdg/latest/xdg/?utm_source=chatgpt.com "xdg - Rust - Docs.rs"
