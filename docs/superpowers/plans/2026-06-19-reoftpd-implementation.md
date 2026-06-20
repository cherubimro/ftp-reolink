# reoftpd Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a hardened, append-only FTP(S) server in Rust that receives Reolink camera uploads, stores them tamper-proof, serves them to scoped read-only accounts, and auto-prunes old files.

**Architecture:** A `libunftp` (tokio/async) FTPS server with a custom `Authenticator` (argon2id accounts from a TOML config) and a custom `StorageBackend`. The security-critical logic — byte-level append-only rules and path scoping — lives in **pure, dependency-free functions** (`append.rs`, `paths.rs`) that are fully unit-tested; the `StorageBackend` impl is a thin adapter over them. DoS controls and TLS wrap the server.

**Tech Stack:** Rust (edition 2021, MSRV 1.85), `libunftp` 0.23, `rustls`, `tokio`, `argon2` + `password-hash`, `serde` + `toml`, `clap`, `tracing`, `nix`, `rcgen`, `governor`. Test-only: `suppaftp`, `tempfile`.

## Global Constraints

- **MSRV:** Rust **1.88** (libunftp 0.23 uses let-chains, which require 1.88). Toolchain pinned to **1.96.0** via `rust-toolchain.toml` (the installed stable). Reflected in `Cargo.toml` `rust-version = "1.88"`.
- **Crates (pinned minor):** `libunftp = "0.23"`, `tokio = { version = "1", features = ["full"] }`, `argon2 = "0.5"`, `password-hash = "0.5"`, `serde = { version = "1", features = ["derive"] }`, `toml = "0.8"`, `clap = { version = "4", features = ["derive"] }`, `tracing = "0.1"`, `tracing-subscriber = "0.3"`, `nix = { version = "0.29", features = ["user", "signal"] }`, `rcgen = "0.13"`, `governor = "0.6"`. Dev: `suppaftp = "6"`, `tempfile = "3"`.
- **Memory safety:** no `unsafe` blocks in our code; add `#![forbid(unsafe_code)]` to `main.rs`/`lib.rs`.
- **Argon2 params:** argon2id, `m = 19456` KiB, `t = 2`, `p = 1` (OWASP). PHC string output (`$argon2id$v=19$...`).
- **Append-only invariant:** a store is permitted only if `start_pos == current_staging_size`; completed files are immutable; violations → reject + log + discard staging.
- **Transfer mode:** force `MODE S` + `STRU F`; reject others.
- **Config file is the single source of truth.** Default path `/etc/reoftpd/reoftpd.toml`.
- **Staging suffix:** `.reoftpd-partial`. **Quarantine dir:** `.quarantine/`. Both hidden from listings and never finalized into the archive.
- **API confirmation:** trait signatures below match libunftp 0.23 / unftp-core as of 2026-02. Before implementing Tasks 6–7 & 11, run `cargo doc --open` (or check docs.rs for the pinned version) and confirm the exact `Authenticator`/`StorageBackend`/`UserDetail`/`Credentials` shapes; adapt the adapter code to the confirmed signatures (the pure-logic tasks do not depend on these).

---

### Task 0: Project scaffold

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `src/main.rs`, `src/lib.rs`, `.gitignore`
- Test: built-in (`src/lib.rs` smoke test)

**Interfaces:**
- Produces: a buildable binary crate `reoftpd` with library `reoftpd` exposing modules; `cargo test` runs.

- [ ] **Step 1: Create `rust-toolchain.toml`**

```toml
[toolchain]
channel = "1.85.0"
components = ["clippy", "rustfmt"]
```

- [ ] **Step 2: Create `Cargo.toml`**

```toml
[package]
name = "reoftpd"
version = "0.1.0"
edition = "2021"
rust-version = "1.85"

[lib]
name = "reoftpd"
path = "src/lib.rs"

[[bin]]
name = "reoftpd"
path = "src/main.rs"

[dependencies]
libunftp = "0.23"
tokio = { version = "1", features = ["full"] }
argon2 = "0.5"
password-hash = { version = "0.5", features = ["std"] }
serde = { version = "1", features = ["derive"] }
toml = "0.8"
clap = { version = "4", features = ["derive"] }
tracing = "0.1"
tracing-subscriber = "0.3"
nix = { version = "0.29", features = ["user", "signal"] }
rcgen = "0.13"
governor = "0.6"

[dev-dependencies]
suppaftp = "6"
tempfile = "3"
```

- [ ] **Step 3: Create `.gitignore`**

```
/target
*.pem
/etc-local/
```

- [ ] **Step 4: Create `src/lib.rs` with a smoke test**

```rust
#![forbid(unsafe_code)]

pub mod append;
pub mod paths;
pub mod hashing;
pub mod config;
pub mod account;
pub mod limits;
pub mod retention;

#[cfg(test)]
mod tests {
    #[test]
    fn harness_runs() {
        assert_eq!(2 + 2, 4);
    }
}
```

(Modules `auth`, `backend`, `tls`, `server` are added in their tasks; leave them out of `lib.rs` until then so it compiles.)

- [ ] **Step 5: Create placeholder module files so `lib.rs` compiles**

Create empty `src/append.rs`, `src/paths.rs`, `src/hashing.rs`, `src/config.rs`, `src/account.rs`, `src/limits.rs`, `src/retention.rs` each containing only a doc comment line `//! <module purpose>`.

- [ ] **Step 6: Create minimal `src/main.rs`**

```rust
#![forbid(unsafe_code)]

fn main() {
    println!("reoftpd");
}
```

- [ ] **Step 7: Build and test**

Run: `cargo test`
Expected: compiles; `harness_runs` PASS.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "chore: scaffold reoftpd Rust crate"
```

---

### Task 1: Append-only core logic (pure)

This is the security heart. No libunftp dependency — pure functions, fully tested.

**Files:**
- Modify: `src/append.rs`
- Test: in-file `#[cfg(test)]`

**Interfaces:**
- Produces:
  - `enum OffsetVerdict { Ok, Overlap, Gap }`
  - `fn classify_offset(start_pos: u64, existing_size: u64) -> OffsetVerdict`
  - `const STAGING_SUFFIX: &str = ".reoftpd-partial";`
  - `fn staging_path(final_path: &std::path::Path) -> std::path::PathBuf`
  - `fn is_reolink_test_file(name: &str) -> bool`
  - `const QUARANTINE_DIR: &str = ".quarantine";`

- [ ] **Step 1: Write failing tests**

```rust
// in src/append.rs
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn offset_equal_is_ok() {
        assert_eq!(classify_offset(100, 100), OffsetVerdict::Ok);
        assert_eq!(classify_offset(0, 0), OffsetVerdict::Ok);
    }

    #[test]
    fn offset_below_existing_is_overlap() {
        assert_eq!(classify_offset(50, 100), OffsetVerdict::Overlap);
        assert_eq!(classify_offset(0, 1), OffsetVerdict::Overlap);
    }

    #[test]
    fn offset_above_existing_is_gap() {
        assert_eq!(classify_offset(101, 100), OffsetVerdict::Gap);
    }

    #[test]
    fn staging_path_appends_suffix() {
        let p = staging_path(Path::new("/srv/reolink/cam/clip.mp4"));
        assert_eq!(p, Path::new("/srv/reolink/cam/clip.mp4.reoftpd-partial"));
    }

    #[test]
    fn detects_reolink_test_file() {
        assert!(is_reolink_test_file("test.txt"));
        assert!(is_reolink_test_file("TestFtp.dat"));
        assert!(!is_reolink_test_file("MD_2026-06-19_120000.mp4"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib append`
Expected: FAIL (items not defined).

- [ ] **Step 3: Implement**

```rust
//! Pure, dependency-free append-only enforcement logic.
use std::path::{Path, PathBuf};

pub const STAGING_SUFFIX: &str = ".reoftpd-partial";
pub const QUARANTINE_DIR: &str = ".quarantine";

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OffsetVerdict {
    Ok,
    Overlap,
    Gap,
}

/// A store may only begin exactly at the current end of the staging file.
pub fn classify_offset(start_pos: u64, existing_size: u64) -> OffsetVerdict {
    use std::cmp::Ordering::*;
    match start_pos.cmp(&existing_size) {
        Equal => OffsetVerdict::Ok,
        Less => OffsetVerdict::Overlap,
        Greater => OffsetVerdict::Gap,
    }
}

/// Hidden staging path for an in-progress upload of `final_path`.
pub fn staging_path(final_path: &Path) -> PathBuf {
    let mut s = final_path.as_os_str().to_owned();
    s.push(STAGING_SUFFIX);
    PathBuf::from(s)
}

/// Reolink uploads a probe file named like `test.*` / `TestFtp*` on "Test".
pub fn is_reolink_test_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("test")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib append`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/append.rs
git commit -m "feat: append-only core logic (offset rule, staging, test-file detection)"
```

---

### Task 2: Path scoping & containment (pure)

**Files:**
- Modify: `src/paths.rs`
- Test: in-file `#[cfg(test)]` using `tempfile`

**Interfaces:**
- Produces:
  - `struct ScopeMap { roots: std::collections::BTreeMap<String, std::path::PathBuf> }` (name → real dir)
  - `impl ScopeMap { fn single(root: PathBuf) -> Self; fn multi(roots: BTreeMap<String, PathBuf>) -> Self; fn resolve(&self, virtual_path: &Path) -> Result<PathBuf, PathError>; fn list_root(&self) -> Vec<String> }`
  - `enum PathError { Traversal, NotFound, OutsideScope }`

- [ ] **Step 1: Write failing tests**

```rust
// in src/paths.rs
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let cam = dir.path().join("front-door");
        fs::create_dir_all(cam.join("2026-06-19")).unwrap();
        fs::write(cam.join("2026-06-19/clip.mp4"), b"data").unwrap();
        (dir, cam)
    }

    #[test]
    fn single_root_resolves_inside() {
        let (_d, cam) = fixture();
        let m = ScopeMap::single(cam.clone());
        let got = m.resolve(std::path::Path::new("/2026-06-19/clip.mp4")).unwrap();
        assert_eq!(got, cam.join("2026-06-19/clip.mp4"));
    }

    #[test]
    fn single_root_rejects_parent_traversal() {
        let (_d, cam) = fixture();
        let m = ScopeMap::single(cam);
        let err = m.resolve(std::path::Path::new("/../secret")).unwrap_err();
        assert_eq!(err, PathError::Traversal);
    }

    #[test]
    fn multi_root_lists_only_allowed_names() {
        let (d, cam) = fixture();
        let mut roots = BTreeMap::new();
        roots.insert("front-door".to_string(), cam);
        roots.insert("driveway".to_string(), d.path().join("driveway"));
        let m = ScopeMap::multi(roots);
        assert_eq!(m.list_root(), vec!["driveway".to_string(), "front-door".to_string()]);
    }

    #[test]
    fn multi_root_maps_first_component_to_real_dir() {
        let (_d, cam) = fixture();
        let mut roots = BTreeMap::new();
        roots.insert("front-door".to_string(), cam.clone());
        let m = ScopeMap::multi(roots);
        let got = m.resolve(std::path::Path::new("/front-door/2026-06-19/clip.mp4")).unwrap();
        assert_eq!(got, cam.join("2026-06-19/clip.mp4"));
    }

    #[test]
    fn multi_root_rejects_unknown_camera() {
        let (_d, cam) = fixture();
        let mut roots = BTreeMap::new();
        roots.insert("front-door".to_string(), cam);
        let m = ScopeMap::multi(roots);
        assert_eq!(m.resolve(std::path::Path::new("/driveway/x")).unwrap_err(), PathError::OutsideScope);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib paths`
Expected: FAIL (items not defined).

- [ ] **Step 3: Implement**

```rust
//! Pure path scoping & jail containment for viewer accounts.
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub enum PathError {
    Traversal,
    NotFound,
    OutsideScope,
}

#[derive(Debug, Clone)]
pub struct ScopeMap {
    roots: BTreeMap<String, PathBuf>,
    single: Option<PathBuf>,
}

/// Reject any virtual path containing `..` or rooted escapes before mapping.
fn normalize(virtual_path: &Path) -> Result<Vec<String>, PathError> {
    let mut out = Vec::new();
    for comp in virtual_path.components() {
        match comp {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(s) => out.push(s.to_string_lossy().into_owned()),
            Component::ParentDir | Component::Prefix(_) => return Err(PathError::Traversal),
        }
    }
    Ok(out)
}

/// Final guard: canonicalized real path must stay within `base`.
fn contained(base: &Path, candidate: &Path) -> Result<PathBuf, PathError> {
    let base_c = base.canonicalize().map_err(|_| PathError::NotFound)?;
    // Canonicalize the existing ancestor, then re-join the non-existent tail,
    // so resolution also defeats symlink escapes.
    let resolved = match candidate.canonicalize() {
        Ok(p) => p,
        Err(_) => candidate.to_path_buf(),
    };
    if resolved.starts_with(&base_c) {
        Ok(resolved)
    } else {
        Err(PathError::Traversal)
    }
}

impl ScopeMap {
    pub fn single(root: PathBuf) -> Self {
        ScopeMap { roots: BTreeMap::new(), single: Some(root) }
    }

    pub fn multi(roots: BTreeMap<String, PathBuf>) -> Self {
        ScopeMap { roots, single: None }
    }

    pub fn list_root(&self) -> Vec<String> {
        self.roots.keys().cloned().collect()
    }

    pub fn resolve(&self, virtual_path: &Path) -> Result<PathBuf, PathError> {
        let parts = normalize(virtual_path)?;
        if let Some(base) = &self.single {
            let joined = parts.iter().fold(base.clone(), |acc, p| acc.join(p));
            return contained(base, &joined);
        }
        let mut iter = parts.into_iter();
        let cam = iter.next().ok_or(PathError::OutsideScope)?;
        let base = self.roots.get(&cam).ok_or(PathError::OutsideScope)?;
        let joined = iter.fold(base.clone(), |acc, p| acc.join(p));
        contained(base, &joined)
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib paths`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/paths.rs
git commit -m "feat: pure path scoping & jail containment (ScopeMap)"
```

---

### Task 3: Password hashing (argon2id)

**Files:**
- Modify: `src/hashing.rs`
- Test: in-file `#[cfg(test)]`

**Interfaces:**
- Produces:
  - `fn hash_password(plain: &str) -> Result<String, HashError>` → PHC string
  - `fn verify_password(plain: &str, phc: &str) -> Result<bool, HashError>`
  - `enum HashError { Hash(String), Parse(String) }`

- [ ] **Step 1: Write failing tests**

```rust
// in src/hashing.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify_roundtrip() {
        let phc = hash_password("s3cret-cam-pw").unwrap();
        assert!(phc.starts_with("$argon2id$"));
        assert!(verify_password("s3cret-cam-pw", &phc).unwrap());
    }

    #[test]
    fn wrong_password_fails() {
        let phc = hash_password("right").unwrap();
        assert!(!verify_password("wrong", &phc).unwrap());
    }

    #[test]
    fn malformed_hash_errors() {
        assert!(verify_password("x", "not-a-phc-string").is_err());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib hashing`
Expected: FAIL (items not defined).

- [ ] **Step 3: Implement**

```rust
//! argon2id password hashing producing PHC strings.
use argon2::{Algorithm, Argon2, Params, Version};
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use password_hash::rand_core::OsRng;

#[derive(Debug)]
pub enum HashError {
    Hash(String),
    Parse(String),
}

fn hasher() -> Argon2<'static> {
    // OWASP argon2id params: m=19456 KiB, t=2, p=1.
    let params = Params::new(19456, 2, 1, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn hash_password(plain: &str) -> Result<String, HashError> {
    let salt = SaltString::generate(&mut OsRng);
    let phc = hasher()
        .hash_password(plain.as_bytes(), &salt)
        .map_err(|e| HashError::Hash(e.to_string()))?;
    Ok(phc.to_string())
}

pub fn verify_password(plain: &str, phc: &str) -> Result<bool, HashError> {
    let parsed = PasswordHash::new(phc).map_err(|e| HashError::Parse(e.to_string()))?;
    Ok(hasher().verify_password(plain.as_bytes(), &parsed).is_ok())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib hashing`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/hashing.rs
git commit -m "feat: argon2id password hashing (PHC strings)"
```

---

### Task 4: Config model & parsing

**Files:**
- Modify: `src/config.rs`
- Test: in-file `#[cfg(test)]`

**Interfaces:**
- Produces (serde structs):
  - `struct Config { server: ServerCfg, archive: ArchiveCfg, limits: LimitsCfg, camera: Vec<CameraCfg>, group: BTreeMap<String, Vec<String>>, viewer: Vec<ViewerCfg> }`
  - `struct ServerCfg { listen: String, port: u16, passive_ports: [u16;2], tls_cert: Option<PathBuf>, tls_key: Option<PathBuf> }`
  - `struct ArchiveCfg { root: PathBuf, retention_days: u64 }`
  - `struct LimitsCfg { max_connections: u32, max_connections_per_ip: u32, new_conns_per_min_per_ip: u32, idle_timeout_secs: u64, min_transfer_rate_bytes_per_sec: u64, failed_login_lockout: LockoutCfg }`
  - `struct LockoutCfg { max_attempts: u32, window_secs: u64, ban_secs: u64 }`
  - `struct CameraCfg { name: String, username: Option<String>, upload_password_hash: String, require_tls: Option<bool> }`
  - `struct ViewerCfg { name: String, password_hash: String, scope: Scope }`
  - `enum Scope { All, List(Vec<String>) }` (deserialize from `"all"` or `["a","b"]`)
  - `fn load(path: &Path) -> Result<Config, ConfigError>` and `fn parse_str(s: &str) -> Result<Config, ConfigError>`
  - `fn validate(&self) -> Result<(), ConfigError>` (unique camera names/usernames, scope names resolve to a camera or group, passive_ports ordered)

- [ ] **Step 1: Write failing tests**

```rust
// in src/config.rs
#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[server]
listen = "0.0.0.0"
port = 21
passive_ports = [50000, 50100]

[archive]
root = "/srv/reolink"
retention_days = 30

[limits]
max_connections = 256
max_connections_per_ip = 8
new_conns_per_min_per_ip = 30
idle_timeout_secs = 120
min_transfer_rate_bytes_per_sec = 1024
failed_login_lockout = { max_attempts = 5, window_secs = 300, ban_secs = 900 }

[[camera]]
name = "front-door"
upload_password_hash = "$argon2id$x"

[group]
outdoor = ["front-door"]

[[viewer]]
name = "admin"
password_hash = "$argon2id$y"
scope = "all"

[[viewer]]
name = "patio"
password_hash = "$argon2id$z"
scope = ["outdoor"]
"#;

    #[test]
    fn parses_sample() {
        let c = parse_str(SAMPLE).unwrap();
        assert_eq!(c.camera.len(), 1);
        assert_eq!(c.archive.retention_days, 30);
        assert!(matches!(c.viewer[0].scope, Scope::All));
        assert!(matches!(&c.viewer[1].scope, Scope::List(v) if v == &vec!["outdoor".to_string()]));
        c.validate().unwrap();
    }

    #[test]
    fn rejects_scope_referencing_unknown_name() {
        let bad = SAMPLE.replace(r#"scope = ["outdoor"]"#, r#"scope = ["nope"]"#);
        let c = parse_str(&bad).unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_camera_name() {
        let dup = format!("{SAMPLE}\n[[camera]]\nname = \"front-door\"\nupload_password_hash = \"$argon2id$q\"\n");
        let c = parse_str(&dup).unwrap();
        assert!(c.validate().is_err());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib config`
Expected: FAIL.

- [ ] **Step 3: Implement**

```rust
//! TOML config model, parsing, and validation.
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum ConfigError {
    Read(String),
    Parse(String),
    Invalid(String),
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerCfg,
    pub archive: ArchiveCfg,
    pub limits: LimitsCfg,
    #[serde(default)]
    pub camera: Vec<CameraCfg>,
    #[serde(default)]
    pub group: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub viewer: Vec<ViewerCfg>,
}

#[derive(Debug, Deserialize)]
pub struct ServerCfg {
    pub listen: String,
    pub port: u16,
    pub passive_ports: [u16; 2],
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    #[serde(default)]
    pub tls_key: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct ArchiveCfg {
    pub root: PathBuf,
    pub retention_days: u64,
}

#[derive(Debug, Deserialize)]
pub struct LimitsCfg {
    pub max_connections: u32,
    pub max_connections_per_ip: u32,
    pub new_conns_per_min_per_ip: u32,
    pub idle_timeout_secs: u64,
    pub min_transfer_rate_bytes_per_sec: u64,
    pub failed_login_lockout: LockoutCfg,
}

#[derive(Debug, Deserialize)]
pub struct LockoutCfg {
    pub max_attempts: u32,
    pub window_secs: u64,
    pub ban_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct CameraCfg {
    pub name: String,
    #[serde(default)]
    pub username: Option<String>,
    pub upload_password_hash: String,
    #[serde(default)]
    pub require_tls: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ViewerCfg {
    pub name: String,
    pub password_hash: String,
    pub scope: Scope,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Scope {
    #[serde(deserialize_with = "all_only")]
    All,
    List(Vec<String>),
}

fn all_only<'de, D: serde::Deserializer<'de>>(d: D) -> Result<(), D::Error> {
    let s = String::deserialize(d)?;
    if s == "all" {
        Ok(())
    } else {
        Err(serde::de::Error::custom("expected \"all\""))
    }
}

impl CameraCfg {
    pub fn login(&self) -> &str {
        self.username.as_deref().unwrap_or(&self.name)
    }
}

pub fn parse_str(s: &str) -> Result<Config, ConfigError> {
    toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))
}

pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let s = std::fs::read_to_string(path).map_err(|e| ConfigError::Read(e.to_string()))?;
    let c = parse_str(&s)?;
    c.validate()?;
    Ok(c)
}

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.passive_ports[0] > self.server.passive_ports[1] {
            return Err(ConfigError::Invalid("passive_ports must be ordered".into()));
        }
        let mut names = BTreeSet::new();
        let mut logins = BTreeSet::new();
        for cam in &self.camera {
            if !names.insert(cam.name.clone()) {
                return Err(ConfigError::Invalid(format!("duplicate camera name {}", cam.name)));
            }
            if !logins.insert(cam.login().to_string()) {
                return Err(ConfigError::Invalid(format!("duplicate username {}", cam.login())));
            }
        }
        for (g, members) in &self.group {
            for m in members {
                if !names.contains(m) {
                    return Err(ConfigError::Invalid(format!("group {g} references unknown camera {m}")));
                }
            }
        }
        for v in &self.viewer {
            if let Scope::List(items) = &v.scope {
                for it in items {
                    if !names.contains(it) && !self.group.contains_key(it) {
                        return Err(ConfigError::Invalid(format!("viewer {} scope references unknown {it}", v.name)));
                    }
                }
            }
        }
        Ok(())
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib config`
Expected: PASS (3 tests). Fix the `Scope` untagged deserialization if `"all"` fails to parse — confirm with `cargo test` output.

- [ ] **Step 5: Commit**

```bash
git add src/config.rs
git commit -m "feat: TOML config model, parsing, and validation"
```

---

### Task 5: Account resolution & User model

**Files:**
- Modify: `src/account.rs`
- Test: in-file `#[cfg(test)]`

**Interfaces:**
- Consumes: `config::{Config, Scope, CameraCfg, ViewerCfg}`, `paths::ScopeMap`.
- Produces:
  - `enum Role { Uploader { home: PathBuf }, Viewer { scope: ScopeMap } }`
  - `struct Account { username: String, password_hash: String, role: Role, require_tls: bool }`
  - `struct Accounts { by_login: BTreeMap<String, Account> }`
  - `fn build(cfg: &Config) -> Accounts` (expands groups → camera names → real dirs; uploader home = `archive.root/<name>`; viewer scope → `ScopeMap`)
  - `impl Accounts { fn get(&self, login: &str) -> Option<&Account> }`

- [ ] **Step 1: Write failing tests**

```rust
// in src/account.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;

    const CFG: &str = r#"
[server]
listen = "0.0.0.0"
port = 21
passive_ports = [50000, 50100]
[archive]
root = "/srv/reolink"
retention_days = 30
[limits]
max_connections = 1
max_connections_per_ip = 1
new_conns_per_min_per_ip = 1
idle_timeout_secs = 1
min_transfer_rate_bytes_per_sec = 1
failed_login_lockout = { max_attempts = 1, window_secs = 1, ban_secs = 1 }
[[camera]]
name = "front-door"
username = "cam-fd"
upload_password_hash = "$argon2id$x"
require_tls = true
[[camera]]
name = "driveway"
upload_password_hash = "$argon2id$y"
[group]
outdoor = ["driveway"]
[[viewer]]
name = "admin"
password_hash = "$argon2id$z"
scope = "all"
[[viewer]]
name = "patio"
password_hash = "$argon2id$w"
scope = ["outdoor", "front-door"]
"#;

    #[test]
    fn uploader_login_uses_username_override() {
        let cfg = parse_str(CFG).unwrap();
        let accts = build(&cfg);
        let a = accts.get("cam-fd").expect("login cam-fd");
        assert!(a.require_tls);
        match &a.role {
            Role::Uploader { home } => assert!(home.ends_with("front-door")),
            _ => panic!("expected uploader"),
        }
    }

    #[test]
    fn uploader_defaults_login_to_name() {
        let cfg = parse_str(CFG).unwrap();
        let accts = build(&cfg);
        assert!(accts.get("driveway").is_some());
    }

    #[test]
    fn viewer_all_is_single_root() {
        let cfg = parse_str(CFG).unwrap();
        let accts = build(&cfg);
        let a = accts.get("admin").unwrap();
        assert!(matches!(a.role, Role::Viewer { .. }));
    }

    #[test]
    fn viewer_scope_expands_group_and_camera_deduped() {
        let cfg = parse_str(CFG).unwrap();
        let accts = build(&cfg);
        let a = accts.get("patio").unwrap();
        if let Role::Viewer { scope } = &a.role {
            let mut names = scope.list_root();
            names.sort();
            assert_eq!(names, vec!["driveway".to_string(), "front-door".to_string()]);
        } else {
            panic!("expected viewer");
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib account`
Expected: FAIL.

- [ ] **Step 3: Implement**

```rust
//! Resolve config into login-keyed accounts with roles and scopes.
use crate::config::{Config, Scope};
use crate::paths::ScopeMap;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum Role {
    Uploader { home: PathBuf },
    Viewer { scope: ScopeMap },
}

#[derive(Debug, Clone)]
pub struct Account {
    pub username: String,
    pub password_hash: String,
    pub role: Role,
    pub require_tls: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Accounts {
    pub by_login: BTreeMap<String, Account>,
}

impl Accounts {
    pub fn get(&self, login: &str) -> Option<&Account> {
        self.by_login.get(login)
    }
}

fn expand_scope(cfg: &Config, scope: &Scope) -> ScopeMap {
    let root = &cfg.archive.root;
    match scope {
        Scope::All => ScopeMap::single(root.clone()),
        Scope::List(items) => {
            let mut names: BTreeSet<String> = BTreeSet::new();
            for it in items {
                if let Some(members) = cfg.group.get(it) {
                    names.extend(members.iter().cloned());
                } else {
                    names.insert(it.clone());
                }
            }
            let mut roots = BTreeMap::new();
            for n in names {
                roots.insert(n.clone(), root.join(&n));
            }
            ScopeMap::multi(roots)
        }
    }
}

pub fn build(cfg: &Config) -> Accounts {
    let mut by_login = BTreeMap::new();
    for cam in &cfg.camera {
        let login = cam.login().to_string();
        by_login.insert(
            login.clone(),
            Account {
                username: login,
                password_hash: cam.upload_password_hash.clone(),
                role: Role::Uploader { home: cfg.archive.root.join(&cam.name) },
                require_tls: cam.require_tls.unwrap_or(false),
            },
        );
    }
    for v in &cfg.viewer {
        by_login.insert(
            v.name.clone(),
            Account {
                username: v.name.clone(),
                password_hash: v.password_hash.clone(),
                role: Role::Viewer { scope: expand_scope(cfg, &v.scope) },
                require_tls: false,
            },
        );
    }
    Accounts { by_login }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib account`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/account.rs
git commit -m "feat: account resolution (roles, scope expansion, login defaulting)"
```

---

### Task 6: DoS limits & lockout tracking

**Files:**
- Modify: `src/limits.rs`
- Test: in-file `#[cfg(test)]`

**Interfaces:**
- Consumes: `config::{LimitsCfg, LockoutCfg}`.
- Produces:
  - `struct ConnTracker` with `fn try_acquire(&self, ip: IpAddr) -> Option<ConnGuard>` (enforces global + per-IP caps; guard releases on drop)
  - `struct LoginTracker` with `fn record_failure(&self, ip: IpAddr, now: Instant)` and `fn is_banned(&self, ip: IpAddr, now: Instant) -> bool`
  - Both constructed from config: `ConnTracker::new(&LimitsCfg)`, `LoginTracker::new(&LockoutCfg)`

- [ ] **Step 1: Write failing tests**

```rust
// in src/limits.rs
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    fn ip(n: u8) -> IpAddr { IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)) }

    #[test]
    fn per_ip_cap_blocks_extra_connection() {
        let t = ConnTracker::new_raw(10, 2);
        let _g1 = t.try_acquire(ip(1)).unwrap();
        let _g2 = t.try_acquire(ip(1)).unwrap();
        assert!(t.try_acquire(ip(1)).is_none());
        // a different IP still gets a slot
        assert!(t.try_acquire(ip(2)).is_some());
    }

    #[test]
    fn dropping_guard_frees_slot() {
        let t = ConnTracker::new_raw(10, 1);
        {
            let _g = t.try_acquire(ip(1)).unwrap();
            assert!(t.try_acquire(ip(1)).is_none());
        }
        assert!(t.try_acquire(ip(1)).is_some());
    }

    #[test]
    fn lockout_after_threshold_then_expires() {
        let t = LoginTracker::new_raw(2, Duration::from_secs(300), Duration::from_secs(900));
        let now = Instant::now();
        assert!(!t.is_banned(ip(1), now));
        t.record_failure(ip(1), now);
        t.record_failure(ip(1), now);
        assert!(t.is_banned(ip(1), now));
        // after ban window
        assert!(!t.is_banned(ip(1), now + Duration::from_secs(901)));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib limits`
Expected: FAIL.

- [ ] **Step 3: Implement**

```rust
//! Connection caps and login-failure lockout (DoS resistance).
use crate::config::{LimitsCfg, LockoutCfg};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct ConnState {
    global: u32,
    per_ip: HashMap<IpAddr, u32>,
}

#[derive(Debug, Clone)]
pub struct ConnTracker {
    max_global: u32,
    max_per_ip: u32,
    state: Arc<Mutex<ConnState>>,
}

pub struct ConnGuard {
    ip: IpAddr,
    state: Arc<Mutex<ConnState>>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut s = self.state.lock().unwrap();
        s.global = s.global.saturating_sub(1);
        if let Some(c) = s.per_ip.get_mut(&self.ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                s.per_ip.remove(&self.ip);
            }
        }
    }
}

impl ConnTracker {
    pub fn new(cfg: &LimitsCfg) -> Self {
        Self::new_raw(cfg.max_connections, cfg.max_connections_per_ip)
    }

    pub fn new_raw(max_global: u32, max_per_ip: u32) -> Self {
        ConnTracker {
            max_global,
            max_per_ip,
            state: Arc::new(Mutex::new(ConnState { global: 0, per_ip: HashMap::new() })),
        }
    }

    pub fn try_acquire(&self, ip: IpAddr) -> Option<ConnGuard> {
        let mut s = self.state.lock().unwrap();
        if s.global >= self.max_global {
            return None;
        }
        let entry = s.per_ip.entry(ip).or_insert(0);
        if *entry >= self.max_per_ip {
            return None;
        }
        *entry += 1;
        s.global += 1;
        Some(ConnGuard { ip, state: Arc::clone(&self.state) })
    }
}

#[derive(Debug, Clone)]
pub struct LoginTracker {
    max_attempts: u32,
    window: Duration,
    ban: Duration,
    state: Arc<Mutex<HashMap<IpAddr, (u32, Instant, Option<Instant>)>>>,
}

impl LoginTracker {
    pub fn new(cfg: &LockoutCfg) -> Self {
        Self::new_raw(
            cfg.max_attempts,
            Duration::from_secs(cfg.window_secs),
            Duration::from_secs(cfg.ban_secs),
        )
    }

    pub fn new_raw(max_attempts: u32, window: Duration, ban: Duration) -> Self {
        LoginTracker {
            max_attempts,
            window,
            ban,
            state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn record_failure(&self, ip: IpAddr, now: Instant) {
        let mut s = self.state.lock().unwrap();
        let entry = s.entry(ip).or_insert((0, now, None));
        if now.duration_since(entry.1) > self.window {
            *entry = (0, now, None);
        }
        entry.0 += 1;
        if entry.0 >= self.max_attempts {
            entry.2 = Some(now);
        }
    }

    pub fn is_banned(&self, ip: IpAddr, now: Instant) -> bool {
        let s = self.state.lock().unwrap();
        if let Some((_, _, Some(since))) = s.get(&ip) {
            now.duration_since(*since) <= self.ban
        } else {
            false
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib limits`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/limits.rs
git commit -m "feat: DoS connection caps and login-failure lockout"
```

---

### Task 7: Retention sweep

**Files:**
- Modify: `src/retention.rs`
- Test: in-file `#[cfg(test)]` using `tempfile` + `filetime`-free mtime via `std`.

**Interfaces:**
- Produces:
  - `struct SweepReport { deleted: Vec<PathBuf>, pruned_dirs: Vec<PathBuf> }`
  - `fn sweep(root: &Path, retention: Duration, quarantine_ttl: Duration, staging_ttl: Duration, now: SystemTime, dry_run: bool) -> std::io::Result<SweepReport>`

- [ ] **Step 1: Write failing tests**

```rust
// in src/retention.rs
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{Duration, SystemTime};

    fn set_mtime(p: &std::path::Path, age: Duration) {
        let t = SystemTime::now() - age;
        let ft = fs::File::open(p).unwrap();
        ft.set_modified(t).unwrap();
    }

    #[test]
    fn deletes_old_keeps_new() {
        let d = tempfile::tempdir().unwrap();
        let cam = d.path().join("cam/2026-01-01");
        fs::create_dir_all(&cam).unwrap();
        let old = cam.join("old.mp4");
        let new = cam.join("new.mp4");
        fs::write(&old, b"x").unwrap();
        fs::write(&new, b"y").unwrap();
        set_mtime(&old, Duration::from_secs(40 * 86400));
        set_mtime(&new, Duration::from_secs(1 * 86400));

        let r = sweep(
            d.path(),
            Duration::from_secs(30 * 86400),
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            SystemTime::now(),
            false,
        ).unwrap();

        assert!(!old.exists());
        assert!(new.exists());
        assert!(r.deleted.iter().any(|p| p.ends_with("old.mp4")));
    }

    #[test]
    fn dry_run_deletes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("old.mp4");
        fs::write(&f, b"x").unwrap();
        set_mtime(&f, Duration::from_secs(40 * 86400));
        let r = sweep(d.path(), Duration::from_secs(30*86400), Duration::from_secs(3600), Duration::from_secs(3600), SystemTime::now(), true).unwrap();
        assert!(f.exists());
        assert_eq!(r.deleted.len(), 1); // reported but not removed
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib retention`
Expected: FAIL.

- [ ] **Step 3: Implement**

```rust
//! Age-based retention sweep (runs outside the FTP path).
use crate::append::{QUARANTINE_DIR, STAGING_SUFFIX};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

#[derive(Debug, Default)]
pub struct SweepReport {
    pub deleted: Vec<PathBuf>,
    pub pruned_dirs: Vec<PathBuf>,
}

fn older_than(path: &Path, ttl: Duration, now: SystemTime) -> bool {
    if let Ok(meta) = std::fs::metadata(path) {
        if let Ok(modified) = meta.modified() {
            if let Ok(age) = now.duration_since(modified) {
                return age > ttl;
            }
        }
    }
    false
}

pub fn sweep(
    root: &Path,
    retention: Duration,
    quarantine_ttl: Duration,
    staging_ttl: Duration,
    now: SystemTime,
    dry_run: bool,
) -> std::io::Result<SweepReport> {
    let mut report = SweepReport::default();
    visit(root, retention, quarantine_ttl, staging_ttl, now, dry_run, &mut report)?;
    Ok(report)
}

fn visit(
    dir: &Path,
    retention: Duration,
    quarantine_ttl: Duration,
    staging_ttl: Duration,
    now: SystemTime,
    dry_run: bool,
    report: &mut SweepReport,
) -> std::io::Result<()> {
    let in_quarantine = dir.file_name().map(|n| n == QUARANTINE_DIR).unwrap_or(false);
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            visit(&path, retention, quarantine_ttl, staging_ttl, now, dry_run, report)?;
            // prune if emptied
            if std::fs::read_dir(&path)?.next().is_none() {
                report.pruned_dirs.push(path.clone());
                if !dry_run {
                    let _ = std::fs::remove_dir(&path);
                }
            }
        } else {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let ttl = if in_quarantine {
                quarantine_ttl
            } else if name.ends_with(STAGING_SUFFIX) {
                staging_ttl
            } else {
                retention
            };
            if older_than(&path, ttl, now) {
                report.deleted.push(path.clone());
                if !dry_run {
                    std::fs::remove_file(&path)?;
                }
            }
        }
    }
    Ok(())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib retention`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/retention.rs
git commit -m "feat: age-based retention sweep with quarantine/staging TTLs"
```

---

### Task 8: Authenticator (libunftp adapter)

**Files:**
- Create: `src/auth.rs`
- Modify: `src/lib.rs` (add `pub mod auth;`)
- Test: in-file async `#[tokio::test]`

**Interfaces:**
- Consumes: `account::{Accounts, Account, Role}`, `hashing::verify_password`, libunftp `auth::{Authenticator, Credentials, AuthenticationError, UserDetail}`.
- Produces:
  - `struct ReoUser { pub login: String, pub role: account::Role, pub require_tls: bool }` implementing libunftp `UserDetail`.
  - `struct ReoAuth { accounts: Accounts }` implementing `Authenticator<ReoUser>` (or the confirmed 0.23 trait shape).
- **Confirm against `cargo doc`** the exact `Authenticator`/`UserDetail`/`Credentials` API for 0.23 before finalizing; the verification logic below is the stable part.

- [ ] **Step 1: Write failing test (verification logic via a thin helper)**

```rust
// in src/auth.rs — test the credential check independent of the trait wiring
#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{Account, Accounts, Role};
    use crate::hashing::hash_password;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn accounts_with(login: &str, plain: &str) -> Accounts {
        let mut by_login = BTreeMap::new();
        by_login.insert(login.to_string(), Account {
            username: login.to_string(),
            password_hash: hash_password(plain).unwrap(),
            role: Role::Uploader { home: PathBuf::from("/srv/reolink/x") },
            require_tls: false,
        });
        Accounts { by_login }
    }

    #[test]
    fn accepts_correct_password() {
        let a = accounts_with("cam", "pw");
        assert!(check_credentials(&a, "cam", "pw").is_some());
    }

    #[test]
    fn rejects_wrong_password_and_unknown_user() {
        let a = accounts_with("cam", "pw");
        assert!(check_credentials(&a, "cam", "nope").is_none());
        assert!(check_credentials(&a, "ghost", "pw").is_none());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib auth`
Expected: FAIL (`check_credentials` undefined).

- [ ] **Step 3: Implement the verification helper + trait wiring**

```rust
//! libunftp Authenticator backed by argon2id accounts.
use crate::account::{Account, Accounts, Role};
use crate::hashing::verify_password;

/// Pure credential check — returns the matched account on success.
pub fn check_credentials<'a>(accounts: &'a Accounts, login: &str, password: &str) -> Option<&'a Account> {
    let acct = accounts.get(login)?;
    match verify_password(password, &acct.password_hash) {
        Ok(true) => Some(acct),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct ReoUser {
    pub login: String,
    pub role: Role,
    pub require_tls: bool,
}

// UserDetail + Authenticator impls go here. Confirm the 0.23 trait shapes via
// `cargo doc` and implement accordingly, e.g.:
//
// impl libunftp::auth::UserDetail for ReoUser {}
// impl std::fmt::Display for ReoUser { ... }
//
// #[async_trait::async_trait]  // if the trait uses async_trait in 0.23
// impl libunftp::auth::Authenticator<ReoUser> for ReoAuth {
//     async fn authenticate(&self, username: &str, creds: &Credentials)
//         -> Result<ReoUser, AuthenticationError> {
//         match check_credentials(&self.accounts, username, creds.password.as_deref().unwrap_or("")) {
//             Some(a) => Ok(ReoUser { login: a.username.clone(), role: a.role.clone(), require_tls: a.require_tls }),
//             None => Err(AuthenticationError::BadPassword),
//         }
//     }
// }
//
// pub struct ReoAuth { pub accounts: Accounts }
```

Implement the commented trait impls against the confirmed API. Keep `check_credentials` as the unit-tested core; the trait `authenticate` must only call it and map the result.

- [ ] **Step 4: Run tests + build**

Run: `cargo test --lib auth && cargo build`
Expected: helper tests PASS; crate builds with the real trait impls.

- [ ] **Step 5: Commit**

```bash
git add src/auth.rs src/lib.rs
git commit -m "feat: argon2id-backed libunftp Authenticator"
```

---

### Task 9: Storage backend (libunftp adapter)

**Files:**
- Create: `src/backend.rs`
- Modify: `src/lib.rs` (add `pub mod backend;`)
- Test: in-file async tests for the append-only `put` path against a temp dir; capability matrix.

**Interfaces:**
- Consumes: `append::{classify_offset, OffsetVerdict, staging_path, is_reolink_test_file, QUARANTINE_DIR}`, `paths::ScopeMap`, `auth::ReoUser`, `account::Role`, libunftp `storage::StorageBackend`.
- Produces: `struct ReoBackend { root: PathBuf }` implementing `StorageBackend<ReoUser>`.
- **Behavioral contract enforced in `put`:**
  1. role must be `Uploader` else `Err(permission denied)`;
  2. compute `staging = staging_path(final)`; `existing = size(staging) or 0`;
  3. `classify_offset(start_pos, existing)` must be `Ok` else discard staging + `Err`;
  4. if `is_reolink_test_file(name)`: write under `<home>/.quarantine/` allowing overwrite, return;
  5. stream bytes appending at `start_pos`; on success atomically `rename(staging → final)`;
  6. if `final` already exists (finalized) → `Err(permission denied)` (no overwrite, no tail-append).
- Capability gate: `get`/`list` allowed for both roles **within scope**; `del`/`rmd`/`rename` always `Err`; `mkd` allowed for uploader only; `put` uploader only.

- [ ] **Step 1: Write a failing test for the append-only decision applied to the filesystem**

Because the libunftp `put` signature streams an `AsyncRead`, extract the decision+write into a testable async helper `store_append(root, home, rel_path, start_pos, bytes) -> Result<u64, StoreError>` and test that directly:

```rust
// in src/backend.rs
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn first_write_then_finalize_creates_file() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path().join("cam");
        fs::create_dir_all(&home).unwrap();
        let n = store_append(&home, std::path::Path::new("clip.mp4"), 0, b"hello").await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(fs::read(home.join("clip.mp4")).unwrap(), b"hello");
        assert!(!home.join("clip.mp4.reoftpd-partial").exists());
    }

    #[tokio::test]
    async fn overlap_offset_is_rejected_and_discarded() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path().join("cam");
        fs::create_dir_all(&home).unwrap();
        // start a partial of size 5
        store_append_partial(&home, std::path::Path::new("clip.mp4"), 0, b"hello").await.unwrap();
        // now an overlapping offset (2 < 5)
        let err = store_append(&home, std::path::Path::new("clip.mp4"), 2, b"XX").await.unwrap_err();
        assert!(matches!(err, StoreError::Overlap));
        assert!(!home.join("clip.mp4.reoftpd-partial").exists()); // discarded
    }

    #[tokio::test]
    async fn write_to_finalized_name_is_rejected() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path().join("cam");
        fs::create_dir_all(&home).unwrap();
        store_append(&home, std::path::Path::new("clip.mp4"), 0, b"hello").await.unwrap();
        let err = store_append(&home, std::path::Path::new("clip.mp4"), 5, b"more").await.unwrap_err();
        assert!(matches!(err, StoreError::Finalized));
    }
}
```

(`store_append_partial` is a test-only variant that writes the staging file without finalizing; implement it behind `#[cfg(test)]`.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib backend`
Expected: FAIL.

- [ ] **Step 3: Implement the helper, then wire the trait**

```rust
//! libunftp StorageBackend with byte-level append-only enforcement.
use crate::append::{classify_offset, staging_path, OffsetVerdict};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

#[derive(Debug)]
pub enum StoreError {
    Overlap,
    Gap,
    Finalized,
    Io(std::io::Error),
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self { StoreError::Io(e) }
}

async fn size_or_zero(p: &Path) -> u64 {
    match tokio::fs::metadata(p).await {
        Ok(m) => m.len(),
        Err(_) => 0,
    }
}

/// Append `bytes` to the staging file at `start_pos`, then finalize.
pub async fn store_append(home: &Path, rel: &Path, start_pos: u64, bytes: &[u8]) -> Result<u64, StoreError> {
    let final_path = home.join(rel);
    if tokio::fs::metadata(&final_path).await.is_ok() {
        return Err(StoreError::Finalized);
    }
    let staging = staging_path(&final_path);
    let existing = size_or_zero(&staging).await;
    match classify_offset(start_pos, existing) {
        OffsetVerdict::Ok => {}
        OffsetVerdict::Overlap => { let _ = tokio::fs::remove_file(&staging).await; return Err(StoreError::Overlap); }
        OffsetVerdict::Gap => { let _ = tokio::fs::remove_file(&staging).await; return Err(StoreError::Gap); }
    }
    if let Some(parent) = staging.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut f = tokio::fs::OpenOptions::new().create(true).append(true).open(&staging).await?;
    f.write_all(bytes).await?;
    f.flush().await?;
    tokio::fs::rename(&staging, &final_path).await?;
    Ok(bytes.len() as u64)
}

#[cfg(test)]
pub async fn store_append_partial(home: &Path, rel: &Path, start_pos: u64, bytes: &[u8]) -> Result<u64, StoreError> {
    let final_path = home.join(rel);
    let staging = staging_path(&final_path);
    let existing = size_or_zero(&staging).await;
    if classify_offset(start_pos, existing) != OffsetVerdict::Ok {
        return Err(StoreError::Overlap);
    }
    if let Some(parent) = staging.parent() { tokio::fs::create_dir_all(parent).await?; }
    let mut f = tokio::fs::OpenOptions::new().create(true).append(true).open(&staging).await?;
    f.write_all(bytes).await?;
    f.flush().await?;
    Ok(bytes.len() as u64)
}

pub struct ReoBackend {
    pub root: PathBuf,
}

// StorageBackend<ReoUser> impl goes here. In `put`, drain the AsyncRead into the
// staging file using the same logic as store_append (stream rather than buffer
// the whole body), branching to the quarantine path when is_reolink_test_file
// is true. del/rmd/rename always return a permission error; mkd/put require
// Role::Uploader; get/list resolve via the user's ScopeMap (Role::Viewer) or the
// uploader home. Confirm the 0.23 StorageBackend trait shape via `cargo doc`.
```

Wire the real `StorageBackend` `put` to stream the `AsyncRead` body into the staging file (chunked copy via `tokio::io::copy`) instead of buffering, but keep the offset decision and finalize/discard behaviour identical to `store_append`. Implement the capability gate in each method per the contract above.

- [ ] **Step 4: Run tests + build**

Run: `cargo test --lib backend && cargo build`
Expected: helper tests PASS (3); crate builds with the trait impl.

- [ ] **Step 5: Commit**

```bash
git add src/backend.rs src/lib.rs
git commit -m "feat: append-only StorageBackend (non-overlap, stage-finalize, capability gate)"
```

---

### Task 10: TLS config & gencert

**Files:**
- Create: `src/tls.rs`
- Modify: `src/lib.rs` (add `pub mod tls;`)
- Test: in-file test that `gencert` returns a parseable cert+key.

**Interfaces:**
- Produces:
  - `fn generate_self_signed(hostnames: &[String]) -> Result<(String /*cert PEM*/, String /*key PEM*/), TlsError>`
  - `fn write_cert_files(cert_pem: &str, key_pem: &str, cert_path: &Path, key_path: &Path) -> std::io::Result<()>` (writes key with mode 0600)

- [ ] **Step 1: Write failing test**

```rust
// in src/tls.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gencert_produces_pem() {
        let (cert, key) = generate_self_signed(&["reoftpd.local".to_string()]).unwrap();
        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("PRIVATE KEY"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib tls`
Expected: FAIL.

- [ ] **Step 3: Implement**

```rust
//! Self-signed certificate generation and key file writing.
use std::path::Path;

#[derive(Debug)]
pub enum TlsError {
    Gen(String),
}

pub fn generate_self_signed(hostnames: &[String]) -> Result<(String, String), TlsError> {
    let cert = rcgen::generate_simple_self_signed(hostnames.to_vec())
        .map_err(|e| TlsError::Gen(e.to_string()))?;
    // rcgen 0.13 API: cert.cert.pem() and cert.key_pair.serialize_pem()
    Ok((cert.cert.pem(), cert.key_pair.serialize_pem()))
}

pub fn write_cert_files(cert_pem: &str, key_pem: &str, cert_path: &Path, key_path: &Path) -> std::io::Result<()> {
    std::fs::write(cert_path, cert_pem)?;
    std::fs::write(key_path, key_pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
```

(Confirm the exact rcgen 0.13 accessor names via `cargo doc`; adjust `.cert.pem()` / `.key_pair.serialize_pem()` if the API differs.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib tls`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/tls.rs src/lib.rs
git commit -m "feat: self-signed cert generation and secure key file writing"
```

---

### Task 11: Server assembly

**Files:**
- Create: `src/server.rs`
- Modify: `src/lib.rs` (add `pub mod server;`)
- Test: integration smoke test deferred to Task 13; here, a build-only milestone plus a unit test for privilege-drop target resolution.

**Interfaces:**
- Consumes: everything above + libunftp `Server`.
- Produces:
  - `async fn run(cfg: config::Config) -> anyhow::Result<()>` — builds the libunftp `Server` with `ReoAuth`, a `ReoBackend` factory, FTPS (if cert configured), passive ports, `idle_session_timeout`, then binds and serves.
  - `fn drop_privileges(user: &str) -> Result<(), PrivError>` (resolve uid/gid via `nix`, setgid then setuid).
  - SIGHUP handler that reloads `Accounts` from disk into a shared `ArcSwap`/`RwLock`.

- [ ] **Step 1: Write failing test for privilege-drop target resolution**

```rust
// in src/server.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_root_user_ids() {
        // "root" exists on all Unix; resolution must succeed and yield uid 0.
        let ids = resolve_user("root").unwrap();
        assert_eq!(ids.uid, 0);
    }

    #[test]
    fn unknown_user_errors() {
        assert!(resolve_user("definitely-not-a-user-xyz").is_err());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib server`
Expected: FAIL.

- [ ] **Step 3: Implement `resolve_user` + `drop_privileges` + `run`**

```rust
//! Server assembly: build libunftp, drop privileges, handle signals.
use nix::unistd::{Gid, Uid, User};

#[derive(Debug)]
pub struct UserIds { pub uid: u32, pub gid: u32 }

#[derive(Debug)]
pub enum PrivError { Lookup(String), Drop(String) }

pub fn resolve_user(name: &str) -> Result<UserIds, PrivError> {
    match User::from_name(name) {
        Ok(Some(u)) => Ok(UserIds { uid: u.uid.as_raw(), gid: u.gid.as_raw() }),
        Ok(None) => Err(PrivError::Lookup(format!("no such user {name}"))),
        Err(e) => Err(PrivError::Lookup(e.to_string())),
    }
}

pub fn drop_privileges(name: &str) -> Result<(), PrivError> {
    let ids = resolve_user(name)?;
    nix::unistd::setgid(Gid::from_raw(ids.gid)).map_err(|e| PrivError::Drop(e.to_string()))?;
    nix::unistd::setuid(Uid::from_raw(ids.uid)).map_err(|e| PrivError::Drop(e.to_string()))?;
    Ok(())
}

// `run` builds the libunftp Server. Pseudostructure (confirm 0.23 builder API):
//
// pub async fn run(cfg: crate::config::Config) -> anyhow::Result<()> {
//     let accounts = crate::account::build(&cfg);
//     let auth = std::sync::Arc::new(crate::auth::ReoAuth { accounts });
//     let root = cfg.archive.root.clone();
//     let conn = crate::limits::ConnTracker::new(&cfg.limits);
//     let server = libunftp::Server::with_authenticator(
//         Box::new(move || crate::backend::ReoBackend { root: root.clone() }),
//         auth,
//     )
//     .passive_ports(cfg.server.passive_ports[0]..=cfg.server.passive_ports[1])
//     .idle_session_timeout(cfg.limits.idle_timeout_secs);
//     let server = if let (Some(cert), Some(key)) = (cfg.server.tls_cert, cfg.server.tls_key) {
//         server.ftps(cert, key)
//     } else { server };
//     let addr = format!("{}:{}", cfg.server.listen, cfg.server.port);
//     // bind (root needed for :21), then drop_privileges("reoftpd"), then listen.
//     server.listen(addr).await?;
//     Ok(())
// }
//
// Confirm: builder method names, whether the connection cap is enforced via a
// libunftp hook or a wrapping accept-loop, and how per-connection peer IP is
// obtained for ConnTracker/LoginTracker. Where libunftp lacks a hook, wrap the
// listener with a tokio accept loop applying ConnTracker before handing off.
```

Implement `run` against the confirmed 0.23 builder API. Enforce `require_tls` in the authenticator/connection path (reject password auth on a plaintext control channel when `user.require_tls`). Wire the SIGHUP reload.

- [ ] **Step 4: Run tests + build**

Run: `cargo test --lib server && cargo build`
Expected: `resolve_user` tests PASS; crate builds.

- [ ] **Step 5: Commit**

```bash
git add src/server.rs src/lib.rs
git commit -m "feat: server assembly, privilege drop, SIGHUP reload"
```

---

### Task 12: CLI wiring

**Files:**
- Modify: `src/main.rs`
- Create: `src/cli.rs`
- Modify: `src/lib.rs` (add `pub mod cli;`)
- Test: in-file tests for `add-camera`/`add-viewer` TOML emission and `hash-password`.

**Interfaces:**
- Produces (clap derive):
  - `enum Command { Serve { config: PathBuf }, Cleanup { config: PathBuf, once: bool, dry_run: bool }, AddCamera { name, username: Option<String>, require_tls: bool }, AddViewer { name, scope: String }, HashPassword, Gencert { hostnames: Vec<String>, cert: PathBuf, key: PathBuf } }`
  - `fn render_camera_entry(name, username: Option<&str>, hash: &str, require_tls: bool) -> String` (TOML snippet)
  - `fn render_viewer_entry(name, hash, scope: &str) -> String`

- [ ] **Step 1: Write failing tests**

```rust
// in src/cli.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn camera_entry_includes_username_and_tls() {
        let s = render_camera_entry("front-door", Some("cam-fd"), "$argon2id$x", true);
        assert!(s.contains("name = \"front-door\""));
        assert!(s.contains("username = \"cam-fd\""));
        assert!(s.contains("require_tls = true"));
        assert!(s.contains("upload_password_hash = \"$argon2id$x\""));
    }

    #[test]
    fn camera_entry_omits_username_when_default() {
        let s = render_camera_entry("driveway", None, "$argon2id$y", false);
        assert!(!s.contains("username ="));
        assert!(!s.contains("require_tls"));
    }

    #[test]
    fn viewer_entry_all_scope() {
        let s = render_viewer_entry("admin", "$argon2id$z", "all");
        assert!(s.contains("scope = \"all\""));
    }

    #[test]
    fn viewer_entry_list_scope() {
        let s = render_viewer_entry("patio", "$argon2id$w", "outdoor,front-door");
        assert!(s.contains(r#"scope = ["outdoor", "front-door"]"#));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib cli`
Expected: FAIL.

- [ ] **Step 3: Implement renderers + clap enum + dispatch in main**

```rust
//! CLI argument model and config-snippet renderers.
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "reoftpd")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Serve { #[arg(long, default_value = "/etc/reoftpd/reoftpd.toml")] config: PathBuf },
    Cleanup {
        #[arg(long, default_value = "/etc/reoftpd/reoftpd.toml")] config: PathBuf,
        #[arg(long)] once: bool,
        #[arg(long)] dry_run: bool,
    },
    AddCamera { name: String, #[arg(long)] username: Option<String>, #[arg(long)] require_tls: bool },
    AddViewer { name: String, #[arg(long)] scope: String },
    HashPassword,
    Gencert {
        #[arg(long, num_args = 1..)] hostnames: Vec<String>,
        #[arg(long)] cert: PathBuf,
        #[arg(long)] key: PathBuf,
    },
}

pub fn render_camera_entry(name: &str, username: Option<&str>, hash: &str, require_tls: bool) -> String {
    let mut s = format!("\n[[camera]]\nname = \"{name}\"\n");
    if let Some(u) = username {
        s.push_str(&format!("username = \"{u}\"\n"));
    }
    s.push_str(&format!("upload_password_hash = \"{hash}\"\n"));
    if require_tls {
        s.push_str("require_tls = true\n");
    }
    s
}

pub fn render_viewer_entry(name: &str, hash: &str, scope: &str) -> String {
    let scope_toml = if scope == "all" {
        "\"all\"".to_string()
    } else {
        let items: Vec<String> = scope.split(',').map(|x| format!("\"{}\"", x.trim())).collect();
        format!("[{}]", items.join(", "))
    };
    format!("\n[[viewer]]\nname = \"{name}\"\npassword_hash = \"{hash}\"\nscope = {scope_toml}\n")
}
```

Then in `src/main.rs`, parse `Cli`, and dispatch: `HashPassword` prompts (read a line from stdin without echo via a small helper, or read from a `REOFTPD_PASSWORD` env var for non-interactive use) and prints `hashing::hash_password`; `AddCamera`/`AddViewer` hash + append the rendered snippet to the config file; `Serve` calls `server::run`; `Cleanup` calls `retention::sweep` and prints the report; `Gencert` calls `tls::generate_self_signed` + `tls::write_cert_files`. Build the tokio runtime for `Serve`.

- [ ] **Step 4: Run tests + build the binary**

Run: `cargo test --lib cli && cargo build`
Expected: 4 renderer tests PASS; binary builds. Manually verify: `cargo run -- hash-password` (with `REOFTPD_PASSWORD=test`) prints a `$argon2id$` string.

- [ ] **Step 5: Commit**

```bash
git add src/cli.rs src/main.rs src/lib.rs
git commit -m "feat: CLI subcommands (serve/cleanup/add-camera/add-viewer/hash-password/gencert)"
```

---

### Task 13: End-to-end integration test

**Files:**
- Create: `tests/integration.rs`
- Create: `tests/fixtures/` (generated at runtime in a tempdir)

**Interfaces:**
- Consumes: the built `reoftpd` server via `reoftpd::server::run` on an ephemeral high port; `suppaftp` as the client.

- [ ] **Step 1: Write the integration test**

```rust
// tests/integration.rs
use std::time::Duration;

// Helper: build a Config pointing at a tempdir archive with one camera (login
// "cam"/password "pw") and one viewer ("admin"/"vp", scope "all"), bound to
// 127.0.0.1:0 (ephemeral). Spawn `reoftpd::server::run` on a tokio task.
// Use a plain-FTP config (no TLS) for the test.

#[tokio::test(flavor = "multi_thread")]
async fn uploader_can_store_once_but_not_overwrite_or_delete() {
    // 1. start server (see helper), get bound addr
    // 2. connect with suppaftp as cam/pw
    // 3. STOR "clip.mp4" with b"hello" -> succeeds
    // 4. assert file exists in archive; STOR same name again -> 550
    // 5. DELE "clip.mp4" -> 550; RMD any -> 550; RETR "clip.mp4" -> 550
    // 6. (resume) REST into existing bytes -> 550
    // Each assertion checks the suppaftp Result is Err with a 5xx for the
    // refused commands and Ok for the permitted STOR.
}

#[tokio::test(flavor = "multi_thread")]
async fn viewer_reads_in_scope_and_cannot_write() {
    // 1. as cam/pw, STOR "clip.mp4"
    // 2. reconnect as admin/vp
    // 3. RETR "front-door/clip.mp4" (or scoped path) -> Ok, bytes match
    // 4. STOR -> 550; DELE -> 550
}
```

Flesh out the bodies with real `suppaftp::AsyncFtpStream` calls and `assert!`/`assert_eq!` on results. Add a 5-second timeout guard around server startup.

- [ ] **Step 2: Run to verify it fails (server helper not wired / behaviour gaps)**

Run: `cargo test --test integration`
Expected: FAIL initially; iterate on `server::run`/`backend` until green.

- [ ] **Step 3: Make it pass**

Fix any gaps surfaced (path mapping for the viewer scope, 550 mapping for denied ops, finalize timing). Re-run until PASS.

- [ ] **Step 4: Run the full suite**

Run: `cargo test`
Expected: all unit + integration tests PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/integration.rs
git commit -m "test: end-to-end append-only + scoped-read integration"
```

---

### Task 14: Packaging, example config, and deployment docs

**Files:**
- Create: `config/reoftpd.example.toml`
- Create: `packaging/reoftpd.service`, `packaging/reoftpd-cleanup.service`, `packaging/reoftpd-cleanup.timer`
- Create: `README.md`

**Interfaces:** none (artifacts).

- [ ] **Step 1: Create `config/reoftpd.example.toml`**

Copy the §4.5 example from the spec verbatim (with placeholder hashes and a comment showing how to generate real ones via `reoftpd hash-password`).

- [ ] **Step 2: Create the hardened systemd service unit `packaging/reoftpd.service`**

```ini
[Unit]
Description=reoftpd append-only FTP archive
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/reoftpd serve --config /etc/reoftpd/reoftpd.toml
User=reoftpd
Group=reoftpd
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/srv/reolink
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
SystemCallFilter=@system-service
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 3: Create `packaging/reoftpd-cleanup.service` and `.timer`**

```ini
# reoftpd-cleanup.service
[Unit]
Description=reoftpd retention sweep

[Service]
Type=oneshot
ExecStart=/usr/local/bin/reoftpd cleanup --once --config /etc/reoftpd/reoftpd.toml
User=reoftpd
Group=reoftpd
ReadWritePaths=/srv/reolink
```

```ini
# reoftpd-cleanup.timer
[Unit]
Description=Run reoftpd retention sweep daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

- [ ] **Step 4: Write `README.md`**

Cover: build (`cargo build --release`), FreeBSD static build note (`RUSTFLAGS`/target), install paths, creating the `reoftpd` user, generating a cert (`reoftpd gencert`), adding cameras/viewers, **firewall**: open port 21 + the passive range, **bind to LAN/VPN, do not expose FTP to the internet**, configuring the Reolink camera (Server, Port, Username, Password, anonymous off), and enabling the systemd units.

- [ ] **Step 5: Final full test + commit**

```bash
cargo test && cargo clippy -- -D warnings
git add config/ packaging/ README.md
git commit -m "docs: packaging, example config, hardened systemd units, deployment guide"
```

---

## Notes for the implementer

- **Pure-logic first:** Tasks 1–7, 10 have zero framework dependency and are fully unit-tested — they are the security core and must stay that way. Tasks 8, 9, 11 are thin adapters; keep logic out of them.
- **Confirm libunftp 0.23 APIs** (Authenticator/UserDetail/Credentials/StorageBackend/Server builder) with `cargo doc --open` before writing the adapter code; the pure functions they call are already proven by tests.
- **Where libunftp lacks a hook** (per-IP connection cap, require_tls enforcement), wrap the TCP accept loop and apply `limits::ConnTracker`/`LoginTracker` and the TLS check before handing the socket to the server.
- **Transfer-mode lock (spec §5.6):** libunftp serves stream/file only; confirm it rejects `MODE B`/`MODE C` and `STRU R`/`P`. If any are accepted, reject them in the backend/command path so the byte-level guarantee holds. Add an integration assertion in Task 13 if the client crate can issue raw `MODE`/`STRU`.
- **Logging (spec §13):** initialise `tracing-subscriber` at startup in `server::run`/`main`. Emit a `tracing` event on every auth success/failure, every finalized upload, and every refused write (`StoreError::{Overlap,Gap,Finalized}` and capability-gate denials) with username/IP + path — these are the tamper-audit records. Emit a `warn` event whenever a `limits` control trips.
- Run `cargo clippy -- -D warnings` and `cargo fmt` before each commit.
