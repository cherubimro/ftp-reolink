# Connection Caps + SIGHUP Reload Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add in-process global + per-account concurrent-session caps, an nftables rule generator for per-IP caps, and SIGHUP config reload (accounts + caps) without stopping the server.

**Architecture:** A `SessionTracker` (replacing the removed `ConnTracker`) holds live session counts; a `PresenceListener` is the accountant (inc on LoggedIn, dec on LoggedOut, keyed by username) and the `Authenticator` is the gate (rejects login at capacity). Accounts live behind `arc_swap::ArcSwap` so a SIGHUP handler can hot-swap them by re-reading the config file. A pure `render_nftables` builds firewall rules from the same config.

**Tech Stack:** Rust 1.96 / libunftp 0.23 / unftp-core 0.1, `arc-swap` (new), `tokio` signal, existing `serde`/`toml`/`clap`/`tracing`/`nix`.

## Global Constraints

- Toolchain Rust 1.96.0; MSRV 1.88. No unsafe (`#![forbid(unsafe_code)]` is crate-wide).
- New dependency: `arc-swap = "1"`.
- `max_connections` = the GLOBAL concurrent-session cap (in-process). `max_connections_per_account` (new, `Option<u32>`, absent = unlimited) = per-username cap. `max_connections_per_ip` = FIREWALL-ONLY (consumed by `render_nftables`, never the FTP process).
- Per-IP in-process caps are infeasible in libunftp 0.23 (no peer IP at LoggedOut) — do NOT attempt them in-process.
- `EventMeta` carries `{ username, trace_id, sequence_number }` — no IP. `PresenceEvent` is `LoggedIn` / `LoggedOut`. Confirm the import path (`libunftp::notification::*` vs `unftp_core::notification::*`) from the installed source before coding the listener.
- Reload must FAIL SAFE: a bad config edit logs an error and leaves the running config unchanged; it must never take the server down.
- What reloads on SIGHUP: accounts (cameras/viewers/groups) + `[limits]` caps. What does NOT (requires restart): bind addr/port, passive_ports, TLS cert/key, idle_session_timeout, failed_logins policy.
- `cargo test` green and `cargo clippy --all-targets -- -D warnings` clean before each commit.

## File Structure
- `src/config.rs` — +`max_connections_per_account` field.
- `src/limits.rs` — remove `ConnTracker`/`ConnGuard`; add `SessionTracker`.
- `src/auth.rs` — `ReoAuth`/`ReoUserProvider` hold `Arc<ArcSwap<Accounts>>`; `ReoAuth` gains the session gate.
- `src/presence.rs` (new) — `ReoPresenceListener`.
- `src/server.rs` — wire tracker + presence; `reload_config`; SIGHUP task; `build_server`/`run` signature changes.
- `src/nftables.rs` (new) — `render_nftables`.
- `src/cli.rs` / `src/main.rs` — `nftables` subcommand; `Serve` passes config path to `run`.
- `config/reoftpd.example.toml`, `README.md` — config + docs.
- `tests/integration.rs` — concurrent-session cap refusal.

---

### Task 1: Config field `max_connections_per_account`

**Files:**
- Modify: `src/config.rs` (the `LimitsCfg` struct + its test config strings)
- Test: in-file `#[cfg(test)]`

**Interfaces:**
- Produces: `LimitsCfg.max_connections_per_account: Option<u32>` (serde `#[serde(default)]`, absent = `None`).

- [ ] **Step 1: Write the failing test**

Add to `src/config.rs` tests (the `SAMPLE` const there does NOT set the new field, so it must default to `None`; add a second case that sets it):

```rust
#[test]
fn max_connections_per_account_defaults_to_none() {
    let c = parse_str(SAMPLE).unwrap();
    assert_eq!(c.limits.max_connections_per_account, None);
}

#[test]
fn max_connections_per_account_parses_when_present() {
    let with = SAMPLE.replace(
        "max_connections_per_ip = 8",
        "max_connections_per_ip = 8\nmax_connections_per_account = 4",
    );
    let c = parse_str(&with).unwrap();
    assert_eq!(c.limits.max_connections_per_account, Some(4));
}
```
(If `SAMPLE` does not contain the exact line `max_connections_per_ip = 8`, read `SAMPLE` and pick a line that is present to anchor the `.replace`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib config::tests::max_connections_per_account`
Expected: FAIL (field does not exist / does not parse).

- [ ] **Step 3: Add the field**

In `struct LimitsCfg`, add (keep existing fields):
```rust
    #[serde(default)]
    pub max_connections_per_account: Option<u32>,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib config`
Expected: PASS (all config tests).

- [ ] **Step 5: Commit**

```bash
git add src/config.rs
git commit -m "feat(config): add optional max_connections_per_account limit"
```

---

### Task 2: `SessionTracker` (replace `ConnTracker`)

**Files:**
- Modify: `src/limits.rs` (remove `ConnTracker`/`ConnGuard` + their tests; add `SessionTracker`)
- Test: in-file `#[cfg(test)]`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `struct SessionTracker` (`Clone`, `Debug`)
  - `fn new(max_global: u32, max_per_account: Option<u32>) -> Self`
  - `fn on_login(&self, username: &str)`
  - `fn on_logout(&self, username: &str)` (saturating; removes the per-account entry at 0)
  - `fn at_capacity(&self, username: &str) -> bool`
  - `fn set_limits(&self, max_global: u32, max_per_account: Option<u32>)`

- [ ] **Step 1: Write the failing tests**

Replace the `ConnTracker` tests in `src/limits.rs` with:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_cap_blocks_when_reached() {
        let t = SessionTracker::new(2, None);
        t.on_login("a");
        t.on_login("b");
        assert!(t.at_capacity("c"));   // global 2 >= 2
        t.on_logout("a");
        assert!(!t.at_capacity("c"));  // global 1 < 2
    }

    #[test]
    fn per_account_cap_blocks_same_user_only() {
        let t = SessionTracker::new(100, Some(1));
        t.on_login("a");
        assert!(t.at_capacity("a"));   // a has 1 >= 1
        assert!(!t.at_capacity("b"));  // b has 0
    }

    #[test]
    fn logout_saturates_and_never_underflows() {
        let t = SessionTracker::new(5, Some(2));
        t.on_logout("ghost");          // no prior login
        assert!(!t.at_capacity("ghost"));
        t.on_login("ghost");
        t.on_logout("ghost");
        t.on_logout("ghost");          // extra logout must not underflow
        assert!(!t.at_capacity("ghost"));
    }

    #[test]
    fn unlimited_per_account_when_none() {
        let t = SessionTracker::new(100, None);
        t.on_login("a");
        t.on_login("a");
        t.on_login("a");
        assert!(!t.at_capacity("a"));  // per-account unlimited; global 3 < 100
    }

    #[test]
    fn set_limits_updates_caps_live() {
        let t = SessionTracker::new(1, None);
        t.on_login("a");
        assert!(t.at_capacity("b"));   // global 1 >= 1
        t.set_limits(2, None);
        assert!(!t.at_capacity("b"));  // global 1 < 2
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib limits`
Expected: FAIL (`SessionTracker` undefined; old `ConnTracker` tests removed).

- [ ] **Step 3: Implement (and delete `ConnTracker`/`ConnGuard`)**

Remove the `ConnTracker`, `ConnGuard`, `ConnState` items entirely. Add:
```rust
//! Concurrent-session limits (global + per-account). Per-IP caps are enforced
//! at the firewall (see `nftables.rs`), not here — libunftp 0.23 gives no peer
//! IP at session end.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct SessionState {
    global: u32,
    per_account: HashMap<String, u32>,
    max_global: u32,
    max_per_account: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct SessionTracker {
    state: Arc<Mutex<SessionState>>,
}

impl SessionTracker {
    pub fn new(max_global: u32, max_per_account: Option<u32>) -> Self {
        SessionTracker {
            state: Arc::new(Mutex::new(SessionState {
                global: 0,
                per_account: HashMap::new(),
                max_global,
                max_per_account,
            })),
        }
    }

    pub fn on_login(&self, username: &str) {
        let mut s = self.state.lock().unwrap();
        s.global = s.global.saturating_add(1);
        *s.per_account.entry(username.to_string()).or_insert(0) += 1;
    }

    pub fn on_logout(&self, username: &str) {
        let mut s = self.state.lock().unwrap();
        s.global = s.global.saturating_sub(1);
        if let Some(c) = s.per_account.get_mut(username) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                s.per_account.remove(username);
            }
        }
    }

    pub fn at_capacity(&self, username: &str) -> bool {
        let s = self.state.lock().unwrap();
        if s.global >= s.max_global {
            return true;
        }
        match s.max_per_account {
            Some(m) => s.per_account.get(username).copied().unwrap_or(0) >= m,
            None => false,
        }
    }

    pub fn set_limits(&self, max_global: u32, max_per_account: Option<u32>) {
        let mut s = self.state.lock().unwrap();
        s.max_global = max_global;
        s.max_per_account = max_per_account;
    }
}
```

- [ ] **Step 4: Confirm nothing else references `ConnTracker`**

Run: `grep -rn 'ConnTracker\|ConnGuard' src/`
Expected: no matches (server.rs did not wire it; if any match exists, it is dead and must be removed as part of this task).

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --lib limits && cargo test`
Expected: PASS (5 limits tests; full suite green).

- [ ] **Step 6: Commit**

```bash
git add src/limits.rs
git commit -m "feat(limits): replace ConnTracker with SessionTracker (global + per-account)"
```

---

### Task 3: Accounts behind `ArcSwap` in auth (reload foundation)

**Files:**
- Modify: `Cargo.toml` (+`arc-swap`), `src/auth.rs`
- Test: in-file `#[cfg(test)]` (existing auth tests adjust to the new field type)

**Interfaces:**
- Consumes: `crate::account::Accounts`.
- Produces:
  - `ReoAuth { pub accounts: Arc<arc_swap::ArcSwap<Accounts>>, pub sessions: Arc<crate::limits::SessionTracker> }`
  - `ReoUserProvider { pub accounts: Arc<arc_swap::ArcSwap<Accounts>> }`
  - (`check_credentials(&Accounts, ...)` is unchanged.)

NOTE: this task introduces the `sessions` field on `ReoAuth` but the capacity check itself is added in Task 4. Here, set up the types and make everything compile + existing tests pass.

- [ ] **Step 1: Add the dependency**

In `Cargo.toml` `[dependencies]`:
```toml
arc-swap = "1"
```

- [ ] **Step 2: Update the auth tests to construct the new shapes**

In `src/auth.rs` tests, wherever a `ReoAuth`/`ReoUserProvider` is built with `accounts: Arc::new(accts)`, change to wrap in `ArcSwap` and pass a tracker. Add a helper at the top of the test module:
```rust
use arc_swap::ArcSwap;
use crate::limits::SessionTracker;

fn swap(accts: Accounts) -> Arc<ArcSwap<Accounts>> {
    Arc::new(ArcSwap::from_pointee(accts))
}
fn unlimited_tracker() -> Arc<SessionTracker> {
    Arc::new(SessionTracker::new(u32::MAX, None))
}
```
Update the `require_tls_rejects_plaintext_accepts_secure` test (and any other `ReoAuth { .. }` construction) to:
```rust
let auth = ReoAuth { accounts: swap(accounts_with("cam", "pw", true)), sessions: unlimited_tracker() };
```
The `check_credentials` unit tests are unaffected (they call `check_credentials(&accounts, ..)` with a plain `Accounts`).

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test --lib auth`
Expected: FAIL (compile errors — `ReoAuth` still has `Arc<Accounts>` and no `sessions`).

- [ ] **Step 4: Update the auth types and bodies**

In `src/auth.rs`:
```rust
use arc_swap::ArcSwap;
use crate::limits::SessionTracker;

#[derive(Debug)]
pub struct ReoAuth {
    pub accounts: Arc<ArcSwap<Accounts>>,
    pub sessions: Arc<SessionTracker>,
}

#[derive(Debug)]
pub struct ReoUserProvider {
    pub accounts: Arc<ArcSwap<Accounts>>,
}
```
In `authenticate`, load the current accounts before checking (the capacity gate is added in Task 4 — for now just load):
```rust
let accts = self.accounts.load();
let password = creds.password.as_deref().unwrap_or("");
match check_credentials(&accts, username, password) {
    Some(acct) => {
        if acct.require_tls && !channel_is_secure(&creds.command_channel_security) {
            return Err(AuthenticationError::new("TLS required for this account"));
        }
        Ok(Principal { username: username.to_string() })
    }
    None => Err(AuthenticationError::BadPassword),
}
```
In `provide_user_detail`:
```rust
let accts = self.accounts.load();
match accts.get(&principal.username) {
    Some(a) => Ok(ReoUser { login: a.username.clone(), role: a.role.clone(), require_tls: a.require_tls }),
    None => Err(UserDetailError::UserNotFound { username: principal.username.clone() }),
}
```
NOTE on the deref: `self.accounts.load()` returns an `arc_swap::Guard` that deref-coerces through `Arc<Accounts>` to `&Accounts`, so `check_credentials(&accts, ..)` and `accts.get(..)` work. If the compiler rejects the coercion, use `let accts = self.accounts.load_full();` (returns `Arc<Accounts>`) and pass `&accts`.

- [ ] **Step 5: Run tests to verify they pass**

`server.rs`'s `build_server` constructs `ReoAuth`/`ReoUserProvider` the old way and will not compile. To keep THIS task's commit green (each task ends green), make the MINIMAL change to `build_server` so it wraps internally — keep its existing external signature `build_server(cfg: &Config, accounts: Accounts)` for now (Task 5 changes the signature). Inside it:
```rust
let accounts = Arc::new(arc_swap::ArcSwap::from_pointee(accounts));
let tracker = Arc::new(crate::limits::SessionTracker::new(
    cfg.limits.max_connections, cfg.limits.max_connections_per_account));
let auth = Arc::new(ReoAuth { accounts: accounts.clone(), sessions: tracker });
let provider = Arc::new(ReoUserProvider { accounts });
```
The existing `build_server_assembles_ok` test keeps calling `build_server(&cfg, account::build(&cfg))` unchanged. Then:

Run: `cargo test --lib auth && cargo build`
Expected: PASS (auth tests); crate builds.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/auth.rs
git commit -m "refactor(auth): hold accounts behind ArcSwap; add sessions field to ReoAuth"
```

---

### Task 4: Session gate + `ReoPresenceListener`

**Files:**
- Modify: `src/auth.rs` (capacity check in `authenticate`)
- Create: `src/presence.rs`
- Modify: `src/lib.rs` (`pub mod presence;`)
- Test: in-file `#[cfg(test)]` in both

**Interfaces:**
- Consumes: `ReoAuth.sessions: Arc<SessionTracker>`, libunftp `PresenceListener`/`PresenceEvent`/`EventMeta`.
- Produces: `presence::ReoPresenceListener { pub tracker: Arc<SessionTracker> }` implementing `PresenceListener`.

- [ ] **Step 1: Write the failing auth gate test**

In `src/auth.rs` tests:
```rust
#[tokio::test]
async fn authenticate_rejected_when_at_global_capacity() {
    let accts = accounts_with("cam", "pw", false);
    let sessions = Arc::new(SessionTracker::new(1, None));
    sessions.on_login("someone-else");          // global now 1 >= 1
    let auth = ReoAuth { accounts: swap(accts), sessions };
    // a Plaintext credential with the right password:
    let creds = make_creds("pw", ChannelEncryptionState::Plaintext); // reuse the helper the require_tls test uses
    let res = auth.authenticate("cam", &creds).await;
    assert!(res.is_err(), "should be refused at capacity even with valid password");
}

#[tokio::test]
async fn authenticate_ok_when_below_capacity() {
    let accts = accounts_with("cam", "pw", false);
    let sessions = Arc::new(SessionTracker::new(2, None));
    sessions.on_login("someone-else");          // global 1 < 2
    let auth = ReoAuth { accounts: swap(accts), sessions };
    let creds = make_creds("pw", ChannelEncryptionState::Plaintext);
    assert!(auth.authenticate("cam", &creds).await.is_ok());
}
```
(If the require_tls test built `Credentials` inline rather than via a `make_creds` helper, extract a small `fn make_creds(password: &str, sec: ChannelEncryptionState) -> Credentials` helper in the test module and use it in both places.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib auth::tests::authenticate_rejected_when_at_global_capacity`
Expected: FAIL (no capacity check yet — returns Ok).

- [ ] **Step 3: Add the gate**

In `authenticate`, inside the `Some(acct)` arm, AFTER the require_tls check and BEFORE returning `Ok`:
```rust
        if self.sessions.at_capacity(username) {
            return Err(AuthenticationError::new("connection limit reached"));
        }
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --lib auth`
Expected: PASS.

- [ ] **Step 5: Write the presence listener (confirm the import path first)**

Read `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/libunftp-0.23.0/src/notification/mod.rs` and `event.rs` to confirm the public path of `PresenceListener`/`PresenceEvent`/`EventMeta` and whether `async_trait` is used. Create `src/presence.rs`:
```rust
//! Connection accountant: maintains live session counts from libunftp presence
//! events (the only hook that sees both ends of a session, keyed by username).
use crate::limits::SessionTracker;
use std::sync::Arc;
// CONFIRM this path from source — likely `libunftp::notification::...`:
use libunftp::notification::{EventMeta, PresenceEvent, PresenceListener};

#[derive(Debug)]
pub struct ReoPresenceListener {
    pub tracker: Arc<SessionTracker>,
}

#[async_trait::async_trait]
impl PresenceListener for ReoPresenceListener {
    async fn receive_presence_event(&self, e: PresenceEvent, m: EventMeta) {
        match e {
            PresenceEvent::LoggedIn => self.tracker.on_login(&m.username),
            PresenceEvent::LoggedOut => self.tracker.on_logout(&m.username),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn login_then_logout_adjusts_tracker() {
        let tracker = Arc::new(SessionTracker::new(1, None));
        let l = ReoPresenceListener { tracker: tracker.clone() };
        let meta = EventMeta { username: "cam".into(), trace_id: "t".into(), sequence_number: 0 };
        l.receive_presence_event(PresenceEvent::LoggedIn, meta.clone()).await;
        assert!(tracker.at_capacity("other"));   // global 1 >= 1
        l.receive_presence_event(PresenceEvent::LoggedOut, meta).await;
        assert!(!tracker.at_capacity("other"));   // global back to 0
    }
}
```
(If `EventMeta` has additional/renamed fields, construct it per the real definition you read.)

- [ ] **Step 6: Register the module + run tests**

Add `pub mod presence;` to `src/lib.rs`.
Run: `cargo test --lib presence && cargo test --lib auth`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/auth.rs src/presence.rs src/lib.rs
git commit -m "feat(auth): reject login at session capacity; add ReoPresenceListener accountant"
```

---

### Task 5: Server wiring + `reload_config` + SIGHUP handler

**Files:**
- Modify: `src/server.rs`, `src/main.rs` (pass config path to `run`)
- Test: in-file `#[cfg(test)]` in `src/server.rs`

**Interfaces:**
- Consumes: `SessionTracker`, `ReoAuth`, `ReoUserProvider`, `ReoPresenceListener`, `ArcSwap`.
- Produces:
  - `build_server(cfg: &Config, accounts: Arc<ArcSwap<Accounts>>, tracker: Arc<SessionTracker>) -> anyhow::Result<Server<ReoBackend, ReoUser>>`
  - `reload_config(path: &Path, accounts: &ArcSwap<Accounts>, tracker: &SessionTracker) -> anyhow::Result<()>`
  - `run(cfg: Config, config_path: PathBuf) -> anyhow::Result<()>`

- [ ] **Step 1: Write the failing `reload_config` test**

In `src/server.rs` tests:
```rust
#[test]
fn reload_swaps_accounts_and_keeps_old_on_invalid() {
    use arc_swap::ArcSwap;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reoftpd.toml");

    // initial valid config with one camera "front-door"
    std::fs::write(&path, MINIMAL_CFG).unwrap();
    let cfg = crate::config::load(&path).unwrap();
    let accounts = std::sync::Arc::new(ArcSwap::from_pointee(crate::account::build(&cfg)));
    let tracker = std::sync::Arc::new(crate::limits::SessionTracker::new(cfg.limits.max_connections, cfg.limits.max_connections_per_account));
    assert!(accounts.load().get("front-door").is_some());
    assert!(accounts.load().get("garage").is_none());

    // valid reload that adds "garage"
    let with_garage = format!("{MINIMAL_CFG}\n[[camera]]\nname = \"garage\"\nupload_password_hash = \"$argon2id$v=19$m=16,t=2,p=1$AAAA$AAAAAAAAAAAAAAAAAAAAAA\"\n");
    std::fs::write(&path, &with_garage).unwrap();
    reload_config(&path, &accounts, &tracker).unwrap();
    assert!(accounts.load().get("garage").is_some(), "reload should add the new camera");

    // invalid reload: garbage TOML — must Err AND leave accounts unchanged
    std::fs::write(&path, "this is not valid toml [[[").unwrap();
    let before = accounts.load().get("garage").is_some();
    assert!(reload_config(&path, &accounts, &tracker).is_err());
    assert_eq!(accounts.load().get("garage").is_some(), before, "bad reload must not change accounts");
}
```
This reuses the `MINIMAL_CFG` const already in `server.rs` tests (a valid config with camera `front-door`). If `MINIMAL_CFG`'s camera is named differently, use that name in the assertions.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib server::tests::reload_swaps_accounts_and_keeps_old_on_invalid`
Expected: FAIL (`reload_config` undefined).

- [ ] **Step 3: Implement `reload_config`, update `build_server`, update `run`**

```rust
use arc_swap::ArcSwap;
use crate::limits::SessionTracker;
use crate::presence::ReoPresenceListener;
use std::path::{Path, PathBuf};

pub fn build_server(
    cfg: &Config,
    accounts: Arc<ArcSwap<crate::account::Accounts>>,
    tracker: Arc<SessionTracker>,
) -> anyhow::Result<libunftp::Server<ReoBackend, ReoUser>> {
    let auth = Arc::new(ReoAuth { accounts: accounts.clone(), sessions: tracker.clone() });
    let provider = Arc::new(ReoUserProvider { accounts });
    let presence = ReoPresenceListener { tracker };

    let lk = &cfg.limits.failed_login_lockout;
    let mut builder = libunftp::ServerBuilder::with_authenticator(Box::new(|| ReoBackend), auth)
        .user_detail_provider(provider)
        .notify_presence(presence)
        .passive_ports(cfg.server.passive_ports[0]..=cfg.server.passive_ports[1])
        .idle_session_timeout(cfg.limits.idle_timeout_secs)
        .failed_logins_policy(libunftp::options::FailedLoginsPolicy::new(
            lk.max_attempts,
            std::time::Duration::from_secs(lk.window_secs),
            libunftp::options::FailedLoginsBlock::UserAndIP,
        ));
    if let (Some(cert), Some(key)) = (cfg.server.tls_cert.clone(), cfg.server.tls_key.clone()) {
        builder = builder.ftps(cert, key);
    }
    Ok(builder.build()?)
}

/// Re-read the config file and hot-swap accounts + caps. Fail-safe: on any
/// error the running config is left unchanged.
pub fn reload_config(
    path: &Path,
    accounts: &ArcSwap<crate::account::Accounts>,
    tracker: &SessionTracker,
) -> anyhow::Result<()> {
    let cfg = crate::config::load(path).map_err(|e| anyhow::anyhow!("reload: {e}"))?;
    ensure_home_dirs(&cfg)?;
    accounts.store(Arc::new(crate::account::build(&cfg)));
    tracker.set_limits(cfg.limits.max_connections, cfg.limits.max_connections_per_account);
    Ok(())
}

pub async fn run(cfg: Config, config_path: PathBuf) -> anyhow::Result<()> {
    ensure_home_dirs(&cfg)?;
    let accounts = Arc::new(ArcSwap::from_pointee(crate::account::build(&cfg)));
    let tracker = Arc::new(SessionTracker::new(
        cfg.limits.max_connections,
        cfg.limits.max_connections_per_account,
    ));

    // SIGHUP -> reload config without stopping the server.
    {
        let accounts = accounts.clone();
        let tracker = tracker.clone();
        let path = config_path.clone();
        tokio::spawn(async move {
            let mut hup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => { tracing::error!("cannot install SIGHUP handler: {e}"); return; }
            };
            while hup.recv().await.is_some() {
                match reload_config(&path, &accounts, &tracker) {
                    Ok(()) => tracing::info!("config reloaded on SIGHUP"),
                    Err(e) => tracing::warn!("SIGHUP reload failed, keeping current config: {e}"),
                }
            }
        });
    }

    let server = build_server(&cfg, accounts, tracker)?;
    server.listen(format!("{}:{}", cfg.server.listen, cfg.server.port)).await?;
    Ok(())
}
```
Update the existing `build_server_assembles_ok` test to build the `ArcSwap` + tracker and call the new `build_server` signature:
```rust
let cfg = crate::config::parse_str(MINIMAL_CFG).unwrap();
let accounts = std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(crate::account::build(&cfg)));
let tracker = std::sync::Arc::new(crate::limits::SessionTracker::new(cfg.limits.max_connections, cfg.limits.max_connections_per_account));
assert!(build_server(&cfg, accounts, tracker).is_ok());
```

- [ ] **Step 4: Update `main.rs` to pass the config path to `run`**

In `src/main.rs`, the `Serve { config }` arm currently does `let cfg = config::load(&config)?; ... server::run(cfg).await`. Change the call to `reoftpd::server::run(cfg, config).await` (pass the `PathBuf`).

- [ ] **Step 5: Run tests + clippy**

Run: `cargo test && cargo clippy --all-targets -- -D warnings`
Expected: PASS; clippy clean.

- [ ] **Step 6: Commit**

```bash
git add src/server.rs src/main.rs
git commit -m "feat(server): wire session caps + presence listener; SIGHUP config reload"
```

---

### Task 6: nftables generator + `nftables` CLI subcommand

**Files:**
- Create: `src/nftables.rs`
- Modify: `src/lib.rs` (`pub mod nftables;`), `src/cli.rs` (`Command::Nftables`), `src/main.rs` (dispatch)
- Test: in-file `#[cfg(test)]`

**Interfaces:**
- Produces: `nftables::render_nftables(cfg: &crate::config::Config) -> String`.

- [ ] **Step 1: Write the failing test**

In `src/nftables.rs`:
```rust
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
max_connections = 256
max_connections_per_ip = 8
new_conns_per_min_per_ip = 30
idle_timeout_secs = 120
min_transfer_rate_bytes_per_sec = 1024
failed_login_lockout = { max_attempts = 5, window_secs = 300, ban_secs = 900 }
"#;

    #[test]
    fn renders_ports_and_counts() {
        let cfg = parse_str(CFG).unwrap();
        let out = render_nftables(&cfg);
        assert!(out.contains("table inet reoftpd"));
        assert!(out.contains("tcp dport 21"));          // control port
        assert!(out.contains("50000-50100"));            // passive range
        assert!(out.contains("ct count over 8"));        // per-IP cap
        assert!(out.contains("ct count over 256"));      // global cap
        assert!(out.contains("ip saddr"));               // keyed per source IP
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib nftables`
Expected: FAIL (`render_nftables` undefined).

- [ ] **Step 3: Implement**

```rust
//! Generate an nftables ruleset enforcing per-source-IP and global connection
//! caps for the FTP control + passive ports. Printed for the admin to apply
//! with `nft -f -`; reoftpd never applies it itself.
use crate::config::Config;

pub fn render_nftables(cfg: &Config) -> String {
    let port = cfg.server.port;
    let plo = cfg.server.passive_ports[0];
    let phi = cfg.server.passive_ports[1];
    let per_ip = cfg.limits.max_connections_per_ip;
    let global = cfg.limits.max_connections;
    format!(
        "table inet reoftpd {{\n\
\tchain input {{\n\
\t\ttype filter hook input priority filter; policy accept;\n\
\t\t# Global cap on the FTP control port (backstop to the in-process session cap)\n\
\t\ttcp dport {port} ct state new ct count over {global} drop\n\
\t\t# Per-source-IP cap on control + passive data ports\n\
\t\ttcp dport {{ {port}, {plo}-{phi} }} ct state new meter reoftpd_perip {{ ip saddr ct count over {per_ip} }} drop\n\
\t}}\n\
}}\n"
    )
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --lib nftables`
Expected: PASS.

- [ ] **Step 5: Wire the CLI subcommand**

Add `pub mod nftables;` to `src/lib.rs`. In `src/cli.rs` `enum Command`, add:
```rust
    /// Print an nftables ruleset (per-IP + global connection caps) from the config
    Nftables {
        #[arg(long, default_value = "/etc/reoftpd/reoftpd.toml")]
        config: std::path::PathBuf,
    },
```
In `src/main.rs` dispatch:
```rust
        Command::Nftables { config } => {
            let cfg = reoftpd::config::load(&config)?;
            print!("{}", reoftpd::nftables::render_nftables(&cfg));
        }
```

- [ ] **Step 6: Build + smoke check + clippy**

Run: `cargo build && cargo run -- nftables --config config/reoftpd.example.toml`
Expected: prints the ruleset (after Task 7 updates the example config; before that, use a valid config path). Then `cargo clippy --all-targets -- -D warnings`.

- [ ] **Step 7: Commit**

```bash
git add src/nftables.rs src/cli.rs src/main.rs src/lib.rs
git commit -m "feat(nftables): generate per-IP/global firewall rules from config"
```

---

### Task 7: Integration test (cap refusal) + docs

**Files:**
- Modify: `tests/integration.rs` (new test), `config/reoftpd.example.toml`, `README.md`

**Interfaces:** none (test + docs).

- [ ] **Step 1: Write the failing integration test**

Add to `tests/integration.rs` a SECOND `#[test]` (its own free ports + server, per the existing pattern) named `global_session_cap_refuses_second_login`. Build the config with `max_connections = 1`, one camera `front-door`/`pw`. Then:
```rust
// First session logs in and stays open; do a PWD so we know LoggedIn fired.
let mut ftp1 = connect_ftp(ctrl);                 // reuse the existing connect helper
ftp1.login("front-door", "pw").unwrap();
let _ = ftp1.pwd().unwrap();                       // ensures the session is established/logged-in

// give the presence event a moment to register (LoggedIn fires just after auth)
std::thread::sleep(std::time::Duration::from_millis(200));

// Second login must be refused while the first holds the only slot.
let mut ftp2 = suppaftp::FtpStream::connect(("127.0.0.1", ctrl)).unwrap();
let second = ftp2.login("front-door", "pw");
assert!(second.is_err(), "second login should be refused at global cap = 1");

// Close the first; a new login then succeeds (LoggedOut decremented the count).
ftp1.quit().ok();
std::thread::sleep(std::time::Duration::from_millis(200));
let mut ftp3 = connect_ftp(ctrl);
assert!(ftp3.login("front-door", "pw").is_ok(), "login should succeed after the first session closed");
ftp3.quit().ok();
```
Reuse the existing `free_port`, `connect_ftp`, and config-building helpers from the first integration test. Keep the `failed_login_lockout.max_attempts` high so the refused login doesn't trip the lockout.

- [ ] **Step 2: Run to verify it fails (or passes once wired)**

Run: `cargo test --test integration global_session_cap_refuses_second_login`
Expected: with Tasks 1–5 done, this should PASS. If it fails because the second login is NOT refused, investigate timing (increase the sleep) — the presence `LoggedIn` event must register before the second login's `at_capacity` check. If it still fails, that is a real wiring bug; report it, do not weaken the assertion.

- [ ] **Step 3: Run it 3 times for flakiness**

Run: `for i in 1 2 3; do cargo test --test integration global_session_cap_refuses_second_login || break; done`
Expected: green all three times. If flaky on the timing sleep, widen it.

- [ ] **Step 4: Update the example config**

In `config/reoftpd.example.toml`, in `[limits]`: add `max_connections_per_account = 4` with a comment, and update comments so: `max_connections` = global concurrent-session cap (enforced in-process); `max_connections_per_account` = per-camera concurrent-session cap (in-process); `max_connections_per_ip` = enforced at the firewall via `reoftpd nftables` (NOT in the FTP process).

- [ ] **Step 5: Update the README**

In `README.md`:
- Move `max_connections` + `max_connections_per_account` to the "enforced in-process" list (global + per-account concurrent sessions).
- State `max_connections_per_ip` is enforced via the generated nftables rules; document `reoftpd nftables --config <path> | sudo nft -f -`.
- Add a "Live config reload" section: editing the config and sending `SIGHUP` (`systemctl reload reoftpd` or `kill -HUP <pid>`) reloads cameras/viewers/groups and caps without dropping connections; bind addr/port, passive ports, TLS, idle timeout, and the failed-logins policy still require a restart; a bad config edit is logged and ignored (server keeps running).
- Add `ExecReload=/bin/kill -HUP $MAINPID` to the documented systemd unit (and to `packaging/reoftpd.service`).

- [ ] **Step 6: Update the systemd unit**

In `packaging/reoftpd.service`, add under `[Service]`:
```ini
ExecReload=/bin/kill -HUP $MAINPID
```

- [ ] **Step 7: Full verify + commit**

Run: `cargo test && cargo clippy --all-targets -- -D warnings`
Expected: all green; clippy clean.
```bash
git add tests/integration.rs config/reoftpd.example.toml README.md packaging/reoftpd.service
git commit -m "test+docs: session-cap integration test; document caps, nftables, SIGHUP reload"
```

---

## Notes for the implementer
- Confirm the libunftp 0.23 notification path (`libunftp::notification` vs `unftp_core::notification`) and the `EventMeta` field set from the installed source before writing `presence.rs`.
- The `ArcSwap::load()` deref to `&Accounts` should work via deref coercion; fall back to `load_full()` (→ `Arc<Accounts>`) if the compiler complains.
- Do NOT attempt per-IP caps in-process — that is the nftables generator's job by design.
- Run `cargo fmt` before each commit.
