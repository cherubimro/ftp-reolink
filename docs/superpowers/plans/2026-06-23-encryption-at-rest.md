# Encryption at Rest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Encrypt every stored clip to age (X25519) public keys on the fly, so plaintext never touches the disk and only an off-server private key can decrypt — opt-in, multi-recipient, layered on the existing append-only model.

**Architecture:** A pure, sync, unit-tested `crypto.rs` (parse recipients, generate identity, stream encrypt/decrypt via the `age` crate). The `StorageBackend::put` path, when recipients are configured, encrypts the incoming stream on the fly (age sync I/O bridged to async via `tokio_util::io::SyncIoBridge` inside `spawn_blocking`), writes ciphertext to staging, names the file `*.age`, and rejects `REST`. CLI gains `genkey`/`decrypt`. Encryption is off when `[encryption]` is absent.

**Tech Stack:** Rust 1.96 / libunftp 0.23, `age = "0.11"` (0.11.3), `tokio-util` (feature `io`, for `SyncIoBridge`), existing tokio/serde/clap.

## Global Constraints

- Toolchain Rust 1.96.0; MSRV 1.88. No unsafe (`#![forbid(unsafe_code)]` crate-wide).
- New deps: `age = "0.11"`, `tokio-util = { version = "0.7", features = ["io"] }`. Confirm the exact age 0.11.3 API from `~/.cargo/registry/src/index.crates.io-*/age-0.11.*/` before coding `crypto.rs`; the round-trip tests pin behavior if a method name differs.
- Encryption is OPT-IN: `[encryption].recipients` absent or empty → behaviour identical to today (no `.age`, plaintext path, `REST` resume supported).
- When encryption is ON: each clip encrypted to ALL recipients; stored name gets a `.age` suffix; **plaintext is never written to disk** (ciphertext streamed to staging); `REST > 0` is rejected (`550`); append-only/no-overwrite/stage-then-finalize/capability-gate/path-containment all still hold on the ciphertext; the Reolink test-file quarantine stays UNENCRYPTED.
- The server holds only public recipient strings. Recipient changes are **restart-required** (not SIGHUP).
- `cargo test` green and `cargo clippy --all-targets -- -D warnings` clean before each commit; `cargo fmt`.

## File Structure
- `src/crypto.rs` (new) — recipients, identity gen, stream encrypt/decrypt. Pure + sync + tested.
- `src/config.rs` — `[encryption]` section + validation (delegates to `crypto::parse_recipients`).
- `src/cli.rs` / `src/main.rs` — `genkey`, `decrypt` subcommands.
- `src/backend.rs` — `ReoBackend.recipients` field; encrypted `put` path.
- `src/server.rs` — parse recipients from config, pass into the `ReoBackend` generator.
- `config/reoftpd.example.toml`, `README.md` — example + "Encryption at rest" section.
- `tests/integration.rs` — encrypted end-to-end test.

---

### Task 1: `crypto.rs` — age helpers (pure, sync, tested)

**Files:**
- Modify: `Cargo.toml` (+`age`, +`tokio-util`)
- Create: `src/crypto.rs`; Modify: `src/lib.rs` (`pub mod crypto;`)
- Test: in-file `#[cfg(test)]`

**Interfaces:**
- Produces:
  - `enum CryptoError { Recipient(String), Identity(String), Encrypt(String), Decrypt(String), Io(std::io::Error) }` (impl Display + Error + From<io::Error>)
  - `fn parse_recipients(strs: &[String]) -> Result<Vec<age::x25519::Recipient>, CryptoError>`
  - `fn generate_identity() -> (String /*public "age1..."*/, String /*secret "AGE-SECRET-KEY-..."*/)`
  - `fn encrypt_stream<R: Read, W: Write>(recipients: &[age::x25519::Recipient], reader: R, writer: W) -> Result<u64, CryptoError>` (returns plaintext bytes processed)
  - `fn decrypt_stream<R: Read, W: Write>(identity: &age::x25519::Identity, reader: R, writer: W) -> Result<u64, CryptoError>`

- [ ] **Step 1: Add dependencies**

In `Cargo.toml` `[dependencies]`:
```toml
age = "0.11"
tokio-util = { version = "0.7", features = ["io"] }
```

- [ ] **Step 2: Write failing tests**

Create `src/crypto.rs` with the test module first:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn round_trip_single_recipient() {
        let (pubkey, secret) = generate_identity();
        let recips = parse_recipients(&[pubkey]).unwrap();
        let plaintext = b"top secret footage";
        let mut ct = Vec::new();
        let n = encrypt_stream(&recips, &plaintext[..], &mut ct).unwrap();
        assert_eq!(n, plaintext.len() as u64);
        assert_ne!(ct.as_slice(), &plaintext[..]); // it's ciphertext
        let id = age::x25519::Identity::from_str(&secret).unwrap();
        let mut pt = Vec::new();
        decrypt_stream(&id, &ct[..], &mut pt).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn multi_recipient_each_can_decrypt() {
        let (p1, s1) = generate_identity();
        let (p2, s2) = generate_identity();
        let recips = parse_recipients(&[p1, p2]).unwrap();
        let mut ct = Vec::new();
        encrypt_stream(&recips, &b"x"[..], &mut ct).unwrap();
        for s in [s1, s2] {
            let id = age::x25519::Identity::from_str(&s).unwrap();
            let mut pt = Vec::new();
            decrypt_stream(&id, &ct[..], &mut pt).unwrap();
            assert_eq!(pt, b"x");
        }
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_recipients(&["not-an-age-key".to_string()]).is_err());
        // a valid-looking key parses:
        let (pubkey, _) = generate_identity();
        assert_eq!(parse_recipients(&[pubkey]).unwrap().len(), 1);
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test --lib crypto`
Expected: FAIL (items not defined).

- [ ] **Step 4: Implement**

At the top of `src/crypto.rs`:
```rust
//! age (X25519) encryption-at-rest helpers. Pure, synchronous, unit-tested.
//! The async backend bridges to these via tokio_util::io::SyncIoBridge.
use std::io::{Read, Write};
use std::str::FromStr;

#[derive(Debug)]
pub enum CryptoError {
    Recipient(String),
    Identity(String),
    Encrypt(String),
    Decrypt(String),
    Io(std::io::Error),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Recipient(e) => write!(f, "invalid age recipient: {e}"),
            CryptoError::Identity(e) => write!(f, "invalid age identity: {e}"),
            CryptoError::Encrypt(e) => write!(f, "encryption failed: {e}"),
            CryptoError::Decrypt(e) => write!(f, "decryption failed: {e}"),
            CryptoError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}
impl std::error::Error for CryptoError {}
impl From<std::io::Error> for CryptoError {
    fn from(e: std::io::Error) -> Self { CryptoError::Io(e) }
}

pub fn parse_recipients(strs: &[String]) -> Result<Vec<age::x25519::Recipient>, CryptoError> {
    strs.iter()
        .map(|s| {
            age::x25519::Recipient::from_str(s.trim())
                .map_err(|e| CryptoError::Recipient(format!("{s}: {e}")))
        })
        .collect()
}

/// Returns (public recipient "age1...", secret identity "AGE-SECRET-KEY-...").
pub fn generate_identity() -> (String, String) {
    let id = age::x25519::Identity::generate();
    let public = id.to_public().to_string();
    // CONFIRM from age 0.11.3 source how the secret serializes — `id.to_string()`
    // returns the bech32 "AGE-SECRET-KEY-..." (it may be a Zeroizing<String>;
    // deref/clone into a plain String). The round-trip test verifies correctness.
    let secret = id.to_string().to_string();
    (public, secret)
}

pub fn encrypt_stream<R: Read, W: Write>(
    recipients: &[age::x25519::Recipient],
    mut reader: R,
    writer: W,
) -> Result<u64, CryptoError> {
    let recs = recipients.iter().map(|r| r as &dyn age::Recipient);
    let encryptor = age::Encryptor::with_recipients(recs)
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;
    let mut out = encryptor
        .wrap_output(writer)
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;
    let n = std::io::copy(&mut reader, &mut out)?;
    // finish() flushes age's final chunk and returns the inner writer; flush it too.
    let mut inner = out.finish().map_err(|e| CryptoError::Encrypt(e.to_string()))?;
    inner.flush()?;
    Ok(n)
}

pub fn decrypt_stream<R: Read, W: Write>(
    identity: &age::x25519::Identity,
    reader: R,
    mut writer: W,
) -> Result<u64, CryptoError> {
    let decryptor = age::Decryptor::new(reader)
        .map_err(|e| CryptoError::Decrypt(e.to_string()))?;
    let mut out = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| CryptoError::Decrypt(e.to_string()))?;
    let n = std::io::copy(&mut out, &mut writer)?;
    Ok(n)
}
```
Add `pub mod crypto;` to `src/lib.rs`. If a method name differs in the installed age 0.11.3 (e.g. `with_recipients` arg shape, `finish()` return, identity `to_string`), adapt to the real API — the tests pin the behavior. Add `secrecy`/`zeroize` handling only if the compiler requires it for the secret string.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --lib crypto`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/crypto.rs src/lib.rs
git commit -m "feat(crypto): age X25519 stream encrypt/decrypt + identity helpers"
```

---

### Task 2: Config `[encryption]` section

**Files:**
- Modify: `src/config.rs`
- Test: in-file `#[cfg(test)]`

**Interfaces:**
- Consumes: `crypto::parse_recipients`.
- Produces: `Config.encryption: Option<EncryptionCfg>` where `struct EncryptionCfg { recipients: Vec<String> }`.

- [ ] **Step 1: Write failing tests**

In `src/config.rs` tests (SAMPLE has no `[encryption]`, so it defaults to `None`):
```rust
#[test]
fn encryption_absent_is_none() {
    let c = parse_str(SAMPLE).unwrap();
    assert!(c.encryption.is_none());
    c.validate().unwrap();
}

#[test]
fn encryption_with_valid_recipient_parses_and_validates() {
    let (pubkey, _) = crate::crypto::generate_identity();
    let s = format!("{SAMPLE}\n[encryption]\nrecipients = [\"{pubkey}\"]\n");
    let c = parse_str(&s).unwrap();
    assert_eq!(c.encryption.as_ref().unwrap().recipients.len(), 1);
    c.validate().unwrap();
}

#[test]
fn encryption_rejects_empty_list_and_bad_key() {
    let empty = format!("{SAMPLE}\n[encryption]\nrecipients = []\n");
    assert!(parse_str(&empty).unwrap().validate().is_err());
    let bad = format!("{SAMPLE}\n[encryption]\nrecipients = [\"not-a-key\"]\n");
    assert!(parse_str(&bad).unwrap().validate().is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib config::tests::encryption`
Expected: FAIL.

- [ ] **Step 3: Implement**

Add the struct and field:
```rust
#[derive(Debug, Deserialize)]
pub struct EncryptionCfg {
    pub recipients: Vec<String>,
}
```
In `struct Config`, add:
```rust
    #[serde(default)]
    pub encryption: Option<EncryptionCfg>,
```
In `Config::validate`, before `Ok(())`, add:
```rust
        if let Some(enc) = &self.encryption {
            if enc.recipients.is_empty() {
                return Err(ConfigError::Invalid("[encryption].recipients must be non-empty".into()));
            }
            crate::crypto::parse_recipients(&enc.recipients)
                .map_err(|e| ConfigError::Invalid(format!("[encryption]: {e}")))?;
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib config`
Expected: PASS (all config tests).

- [ ] **Step 5: Commit**

```bash
git add src/config.rs
git commit -m "feat(config): optional [encryption].recipients with validation"
```

---

### Task 3: CLI `genkey` and `decrypt`

**Files:**
- Modify: `src/cli.rs`, `src/main.rs`
- Test: in-file `#[cfg(test)]` for any pure helper; manual smoke for the subcommands.

**Interfaces:**
- Consumes: `crypto::{generate_identity, decrypt_stream}`.
- Produces: `Command::Genkey { output: Option<PathBuf> }`, `Command::Decrypt { identity: PathBuf, output: Option<PathBuf>, files: Vec<PathBuf> }`.

- [ ] **Step 1: Add the clap variants**

In `src/cli.rs` `enum Command`, add:
```rust
    /// Generate an age keypair (public recipient -> config; private identity -> off-server)
    Genkey {
        #[arg(long)]
        output: Option<std::path::PathBuf>,
    },
    /// Decrypt downloaded *.age files locally with your age identity
    Decrypt {
        #[arg(long)]
        identity: std::path::PathBuf,
        #[arg(long)]
        output: Option<std::path::PathBuf>,
        #[arg(required = true)]
        files: Vec<std::path::PathBuf>,
    },
```

- [ ] **Step 2: Implement dispatch in `src/main.rs`**

```rust
        Command::Genkey { output } => {
            let (public, secret) = reoftpd::crypto::generate_identity();
            match output {
                Some(path) => {
                    use std::io::Write;
                    #[cfg(unix)]
                    let mut f = {
                        use std::os::unix::fs::OpenOptionsExt;
                        std::fs::OpenOptions::new().write(true).create(true).truncate(true)
                            .mode(0o600).open(&path)?
                    };
                    #[cfg(not(unix))]
                    let mut f = std::fs::File::create(&path)?;
                    writeln!(f, "{secret}")?;
                    eprintln!("Private identity written to {} (mode 0600). KEEP IT OFF THE SERVER.", path.display());
                }
                None => {
                    eprintln!("# KEEP THE SECRET BELOW OFF THE SERVER. Losing it = unrecoverable archive.");
                    println!("{secret}");
                }
            }
            eprintln!("Add this PUBLIC recipient to [encryption].recipients (and keep a backup key):");
            println!("{public}");
        }
        Command::Decrypt { identity, output, files } => {
            let id_text = std::fs::read_to_string(&identity)?;
            // an identity file may contain comment lines (starting with '#'); take the first key line.
            let key_line = id_text.lines().find(|l| l.trim_start().starts_with("AGE-SECRET-KEY-"))
                .ok_or_else(|| anyhow::anyhow!("no AGE-SECRET-KEY- line in {}", identity.display()))?;
            let id = <age::x25519::Identity as std::str::FromStr>::from_str(key_line.trim())
                .map_err(|e| anyhow::anyhow!("bad identity: {e}"))?;
            for input in &files {
                let stem = input.file_name().and_then(|n| n.to_str())
                    .and_then(|n| n.strip_suffix(".age"))
                    .ok_or_else(|| anyhow::anyhow!("{} does not end in .age", input.display()))?;
                let out_path = match &output {
                    Some(dir) => dir.join(stem),
                    None => input.with_file_name(stem),
                };
                let rd = std::fs::File::open(input)?;
                let wr = std::fs::File::create(&out_path)?;
                reoftpd::crypto::decrypt_stream(&id, rd, wr)
                    .map_err(|e| anyhow::anyhow!("{}: {e}", input.display()))?;
                eprintln!("decrypted {} -> {}", input.display(), out_path.display());
            }
        }
```
Add `use age;` import access as needed (or fully-qualify). Add `age` is already a dependency.

- [ ] **Step 3: Build + smoke test**

Run:
```bash
cargo build
REC=$(cargo run --quiet -- genkey --output /tmp/reoftpd-id.txt 2>/dev/null | tail -1)
echo "hello" > /tmp/clip.txt
# encrypt with the age CLI-compatible path via a tiny round-trip using the public key is covered by tests;
cargo run --quiet -- decrypt --identity /tmp/reoftpd-id.txt /tmp/nonexistent.age 2>&1 | head -1   # expect a clear error
cargo run --quiet -- --help | grep -E 'genkey|decrypt'
```
Expected: `--help` lists `genkey` and `decrypt`; `genkey` writes the identity file and prints a recipient.

- [ ] **Step 4: Run the suite + clippy**

Run: `cargo test && cargo clippy --all-targets -- -D warnings`
Expected: green; clippy clean.

- [ ] **Step 5: Commit**

```bash
git add src/cli.rs src/main.rs
git commit -m "feat(cli): genkey and decrypt subcommands"
```

---

### Task 4: Backend on-the-fly encryption + server wiring

**Files:**
- Modify: `src/backend.rs`, `src/server.rs`
- Test: in-file async tests in `src/backend.rs`

**Interfaces:**
- Consumes: `crypto::encrypt_stream`, `append::staging_path`, `tokio_util::io::SyncIoBridge`, `config::EncryptionCfg`, `crypto::parse_recipients`.
- Produces: `ReoBackend { recipients: Option<std::sync::Arc<Vec<age::x25519::Recipient>>> }` with `ReoBackend::new(recipients: Option<Arc<Vec<age::x25519::Recipient>>>) -> Self`; `fn age_suffix(path: &Path) -> PathBuf`; `async fn store_encrypted(real_final: &Path, recipients: Arc<Vec<age::x25519::Recipient>>, input) -> Result<u64, StoreError>`.

- [ ] **Step 1: Write the failing test for `store_encrypted`**

In `src/backend.rs` tests:
```rust
#[tokio::test]
async fn store_encrypted_writes_ciphertext_that_decrypts() {
    use std::str::FromStr;
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("cam");
    std::fs::create_dir_all(&home).unwrap();
    let (pubkey, secret) = crate::crypto::generate_identity();
    let recips = std::sync::Arc::new(crate::crypto::parse_recipients(&[pubkey]).unwrap());
    let plaintext = b"camera footage bytes";

    let final_path = home.join("clip.mp4.age");
    let n = store_encrypted(&final_path, recips.clone(), &plaintext[..]).await.unwrap();
    assert_eq!(n, plaintext.len() as u64);

    let stored = std::fs::read(&final_path).unwrap();
    assert_ne!(stored.as_slice(), &plaintext[..], "stored file must be ciphertext, not plaintext");
    assert!(!home.join("clip.mp4.age.reoftpd-partial").exists(), "staging cleaned");

    // decrypts back to the original
    let id = age::x25519::Identity::from_str(&secret).unwrap();
    let mut out = Vec::new();
    crate::crypto::decrypt_stream(&id, &stored[..], &mut out).unwrap();
    assert_eq!(out, plaintext);
}

#[tokio::test]
async fn store_encrypted_refuses_existing_finalized() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("cam");
    std::fs::create_dir_all(&home).unwrap();
    let (pubkey, _) = crate::crypto::generate_identity();
    let recips = std::sync::Arc::new(crate::crypto::parse_recipients(&[pubkey]).unwrap());
    let p = home.join("clip.mp4.age");
    store_encrypted(&p, recips.clone(), &b"a"[..]).await.unwrap();
    let err = store_encrypted(&p, recips, &b"b"[..]).await.unwrap_err();
    assert!(matches!(err, StoreError::Finalized));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib backend::tests::store_encrypted`
Expected: FAIL (`store_encrypted`/field not defined).

- [ ] **Step 3: Implement the field, `age_suffix`, and `store_encrypted`**

Change `ReoBackend` to carry recipients:
```rust
#[derive(Debug)]
pub struct ReoBackend {
    pub recipients: Option<std::sync::Arc<Vec<age::x25519::Recipient>>>,
}

impl ReoBackend {
    pub fn new(recipients: Option<std::sync::Arc<Vec<age::x25519::Recipient>>>) -> Self {
        ReoBackend { recipients }
    }
}
```
Update EVERY construction site to the new form: the `StorageBackend<DefaultUser>` stub references the type only (no change); existing backend tests that build `ReoBackend` become `ReoBackend::new(None)`. (Search `ReoBackend` in `src/` and fix each literal.)

Add:
```rust
/// Append the `.age` suffix to a resolved real path (clip.mp4 -> clip.mp4.age).
pub fn age_suffix(path: &std::path::Path) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".age");
    std::path::PathBuf::from(s)
}

/// On-the-fly encrypted store: stream `input` through age to a ciphertext staging
/// file, then atomically finalize. Plaintext never lands on disk.
pub async fn store_encrypted<R>(
    real_final: &std::path::Path,
    recipients: std::sync::Arc<Vec<age::x25519::Recipient>>,
    input: R,
) -> Result<u64, StoreError>
where
    R: tokio::io::AsyncRead + Send + Unpin + 'static,
{
    if tokio::fs::try_exists(real_final).await.unwrap_or(false) {
        return Err(StoreError::Finalized);
    }
    let staging = crate::append::staging_path(real_final);
    if let Some(parent) = staging.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let staging_for_task = staging.clone();
    let bridge = tokio_util::io::SyncIoBridge::new(input); // created in async context, used in spawn_blocking
    let n = tokio::task::spawn_blocking(move || -> Result<u64, crate::crypto::CryptoError> {
        let file = std::fs::File::create(&staging_for_task)?;
        crate::crypto::encrypt_stream(&recipients, bridge, file)
    })
    .await
    .map_err(|e| StoreError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?
    .map_err(|e| StoreError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

    // Finalize: no-clobber hard link, same as the plaintext path.
    match tokio::fs::hard_link(&staging, real_final).await {
        Ok(()) => {
            let _ = tokio::fs::remove_file(&staging).await;
            Ok(n)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = tokio::fs::remove_file(&staging).await;
            Err(StoreError::Finalized)
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&staging).await;
            Err(StoreError::Io(e))
        }
    }
}
```

- [ ] **Step 4: Wire `store_encrypted` into the `put` trait method**

In the `StorageBackend::put` impl, inside the uploader branch, AFTER the capability check and the Reolink test-file/quarantine handling (test files stay plaintext), and BEFORE the existing plaintext `store_stream` call, add:
```rust
        if let Some(recipients) = &self.recipients {
            if start_pos != 0 {
                // REST/resume is not supported for encrypted uploads.
                return Err(unftp_core::storage::ErrorKind::PermissionDenied.into());
            }
            let real_final = age_suffix(&resolved); // `resolved` = the real path from user_view().resolve(path)
            return store_encrypted(&real_final, recipients.clone(), input)
                .await
                .map_err(map_store_error); // reuse the existing StoreError -> unftp Error mapping
        }
        // ... existing plaintext store_stream path unchanged ...
```
Use the SAME path-resolution (`user_view(user).resolve(...)`) and the SAME `StoreError -> ErrorKind` mapping the plaintext path already uses (name it consistently; if there is an inline match, factor it into `fn map_store_error(e: StoreError) -> unftp_core::storage::Error` and use it in both places). Keep the quarantine test-file branch BEFORE this (test files are never encrypted).

- [ ] **Step 5: Pass recipients from config in `src/server.rs`**

In `build_server`, before constructing the builder, parse the recipients and capture them in the generator closure:
```rust
    let recipients = match &cfg.encryption {
        Some(enc) => Some(std::sync::Arc::new(
            crate::crypto::parse_recipients(&enc.recipients)
                .map_err(|e| anyhow::anyhow!("encryption recipients: {e}"))?,
        )),
        None => None,
    };
    let server = libunftp::ServerBuilder::with_authenticator(
        Box::new(move || ReoBackend::new(recipients.clone())),
        auth,
    )
    // ... rest unchanged ...
```
Update the `build_server_assembles_ok` test if it referenced `ReoBackend` directly (it uses `build_server`, so likely no change).

- [ ] **Step 6: Run tests + clippy**

Run: `cargo test && cargo clippy --all-targets -- -D warnings`
Expected: green; clippy clean. (Fix any remaining `ReoBackend` construction sites flagged by the compiler.)

- [ ] **Step 7: Commit**

```bash
git add src/backend.rs src/server.rs
git commit -m "feat(backend): on-the-fly age encryption of uploads (.age, reject REST)"
```

---

### Task 5: Integration test + docs

**Files:**
- Modify: `tests/integration.rs`, `config/reoftpd.example.toml`, `README.md`

- [ ] **Step 1: Write the encrypted end-to-end test**

Add a third `#[test]` to `tests/integration.rs` named `encrypted_upload_is_ciphertext_on_disk_and_decryptable`. Build the config with an `[encryption]` section (generate a keypair in the test with `reoftpd::crypto::generate_identity`, put the public key in the TOML, keep the secret). One camera `front-door`/`pw`. Then:
```rust
// upload a known plaintext
let mut up = connect_ftp(ctrl);
up.login("front-door", "pw").unwrap();
let body = b"END TO END ARCHIVE BYTES";
up.put_file("clip.mp4", &mut &body[..]).unwrap();
up.quit().ok();

// on-disk file is <root>/front-door/clip.mp4.age and is ciphertext (not the plaintext)
let stored_path = archive_root.join("front-door/clip.mp4.age");
let stored = std::fs::read(&stored_path).expect("encrypted file on disk");
assert_ne!(stored.as_slice(), &body[..], "archive file must be ciphertext");
assert!(!archive_root.join("front-door/clip.mp4").exists(), "no plaintext file");

// viewer downloads the .age ciphertext
let mut vw = connect_ftp(ctrl);
vw.login("admin", "vp").unwrap();
let downloaded = vw.retr_as_buffer("/front-door/clip.mp4.age").unwrap().into_inner();
vw.quit().ok();
assert_ne!(downloaded.as_slice(), &body[..]);

// decrypt with the test identity recovers the exact original
let id = <age::x25519::Identity as std::str::FromStr>::from_str(&secret).unwrap();
let mut out = Vec::new();
reoftpd::crypto::decrypt_stream(&id, &downloaded[..], &mut out).unwrap();
assert_eq!(out, body);
```
Reuse the existing `free_port`/`connect_ftp`/config-building helpers; its own ports + server. Set `failed_login_lockout.max_attempts` high. The viewer scope is `all`, so it reads `/front-door/...`.

- [ ] **Step 2: Run it (3x for flakiness) + full suite**

Run: `cargo test --test integration encrypted_upload_is_ciphertext_on_disk_and_decryptable` (3 times), then `cargo test`.
Expected: green and deterministic. If the upload fails, check that `put` is taking the encrypted branch and that the on-disk name is `.age`.

- [ ] **Step 3: Update the example config**

In `config/reoftpd.example.toml`, add a commented-out block:
```toml
# Optional: encrypt every stored clip to one or more age (X25519) public keys.
# The private key NEVER goes on this server; viewers decrypt downloaded *.age
# files locally. Generate keys with `reoftpd genkey`. Changing this needs a restart.
# [encryption]
# recipients = ["age1exampleRecipientPublicKeyGoesHere", "age1backupKey"]
```

- [ ] **Step 4: Add the README "Encryption at rest" section**

In `README.md`, add a section documenting: what it protects (stolen VPS/disks/later-root → ciphertext only) and the honest caveat (at-rest, not end-to-end — plaintext is briefly in server RAM during upload); `reoftpd genkey` (keep the identity OFF the server, configure a backup recipient, losing the key = unrecoverable); the `[encryption].recipients` config (restart-required); that uploads become `*.age` and `REST`/resume is disabled when on; and the viewer decrypt step (`reoftpd decrypt -i identity.txt clip.mp4.age`, or `age -d -i identity.txt clip.mp4.age`). Note ChaCha20-Poly1305 is fast without AES-NI (good on old VPS).

- [ ] **Step 5: Final verify + commit**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: all green; clippy clean.
```bash
git add tests/integration.rs config/reoftpd.example.toml README.md
git commit -m "test+docs: encrypted end-to-end test; document encryption at rest"
```

---

## Notes for the implementer
- Confirm the age 0.11.3 API (`with_recipients` arg/return, `wrap_output`, `StreamWriter::finish`, `Decryptor::new`/`decrypt`, `x25519::Identity` secret serialization) from the installed crate source before Task 1; the round-trip tests are the behavioral contract.
- `SyncIoBridge::new` must be constructed in the async context and then moved into `spawn_blocking` (where its blocking `Read` is used).
- Test files (Reolink probes) are NEVER encrypted — keep that branch ahead of the encryption branch in `put`.
- Run `cargo fmt` before each commit.
