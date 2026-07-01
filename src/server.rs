//! Server assembly: builds the libunftp `Server`, creates camera home directories,
//! and runs the listener. Also provides privilege-drop utilities (unit-tested).
//!
//! # Builder wiring
//!
//! `ServerBuilder::with_authenticator` is only implemented for `DefaultUser` and
//! requires `Storage: StorageBackend<DefaultUser>`. We call it first (with our
//! `ReoAuth`), then immediately call `.user_detail_provider(provider)` which
//! switches the builder's `User` type parameter from `DefaultUser` to `ReoUser`.
//! The resulting `Server<ReoBackend, ReoUser>` only ever serves `ReoUser` sessions.
//! The `StorageBackend<DefaultUser>` stub in `backend.rs` satisfies the type bound
//! but is never called at runtime.
//!
//! # Confirmed libunftp 0.23 builder API
//!
//! - Re-export: `libunftp::{Server, ServerBuilder}` (from `src/lib.rs` line 53)
//! - `ServerBuilder::with_authenticator(generator, auth)` — only on `DefaultUser`
//! - `.user_detail_provider(Arc<P>)` — switches `User` type; only on `DefaultUser` builder
//! - `.passive_ports(RangeInclusive<u16>)` — on all `ServerBuilder<S, U>`
//! - `.idle_session_timeout(u64 secs)` — on all `ServerBuilder<S, U>`
//! - `.failed_logins_policy(FailedLoginsPolicy)` — on all `ServerBuilder<S, U>`
//! - `.ftps(certs_file, key_file)` — on all `ServerBuilder<S, U>`
//! - `.notify_presence(impl PresenceListener + 'static)` — on all `ServerBuilder<S, U>`
//! - `.build() -> Result<Server<S, U>, ServerError>` — on all `ServerBuilder<S, U>`
//! - `Server::listen(addr: impl Into<String> + Debug) -> Result<(), ServerError>` — async
//!
//! # Known limitations (libunftp 0.23)
//!
//! 1. **No in-process privilege drop around `listen`.** `Server::listen` binds the
//!    socket internally. `PreboundListener` is `pub(super)` and not exposed via the
//!    public API. The "bind as root then setuid" pattern is NOT available. Production
//!    privilege separation MUST use systemd `AmbientCapabilities=CAP_NET_BIND_SERVICE`
//!    plus `User=reoftpd` (documented in Task 14). `drop_privileges` is provided for
//!    completeness and future use but `run` does NOT call it.

use crate::account::Accounts;
use crate::auth::{ReoAuth, ReoUser, ReoUserProvider};
use crate::backend::ReoBackend;
use crate::config::Config;
use crate::limits::SessionTracker;
use crate::presence::ReoPresenceListener;
use anyhow::Context as _;
use arc_swap::ArcSwap;
use libunftp::options::{FailedLoginsBlock, FailedLoginsPolicy};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Server builder
// ---------------------------------------------------------------------------

/// Build the configured libunftp server (does not listen).
///
/// This function is `pub` so that integration tests and the `run` function can
/// reuse it. It does NOT bind any port.
pub fn build_server(
    cfg: &Config,
    accounts: Arc<ArcSwap<Accounts>>,
    tracker: Arc<SessionTracker>,
) -> anyhow::Result<libunftp::Server<ReoBackend, ReoUser>> {
    let auth = Arc::new(ReoAuth {
        accounts: accounts.clone(),
        sessions: tracker.clone(),
    });
    let provider = Arc::new(ReoUserProvider {
        accounts: accounts.clone(),
    });
    let presence = ReoPresenceListener { tracker };

    let lk = &cfg.limits.failed_login_lockout;

    // Parse optional encryption recipients from config.
    let recipients = match &cfg.encryption {
        Some(enc) => Some(std::sync::Arc::new(
            crate::crypto::parse_recipients(&enc.recipients)
                .map_err(|e| anyhow::anyhow!("encryption recipients: {e}"))?,
        )),
        None => None,
    };

    // Step 1: with_authenticator — requires Storage: StorageBackend<DefaultUser>.
    //   The stub impl in backend.rs satisfies that bound.
    // Step 2: user_detail_provider — switches User from DefaultUser to ReoUser.
    //   After this point the builder is ServerBuilder<ReoBackend, ReoUser>.
    // Step 3: notify_presence — wires the session tracker for login/logout events.
    let mut builder = libunftp::ServerBuilder::with_authenticator(
        Box::new(move || ReoBackend::new(recipients.clone())),
        auth,
    )
    .user_detail_provider(provider)
    .notify_presence(presence)
    .passive_ports(cfg.server.passive_ports[0]..=cfg.server.passive_ports[1])
    .idle_session_timeout(cfg.limits.idle_timeout_secs)
    .failed_logins_policy(FailedLoginsPolicy::new(
        lk.max_attempts,
        Duration::from_secs(lk.window_secs),
        FailedLoginsBlock::UserAndIP,
    ));

    // Advertise a fixed IP/DNS in PASV replies when configured (required behind
    // NAT/DMZ so remote clients dial back a reachable address). libunftp's
    // `From<&str>` maps a parseable IPv4 to `PassiveHost::Ip`, else `PassiveHost::Dns`.
    if let Some(host) = cfg.server.passive_host.as_deref() {
        builder = builder.passive_host(host);
    }

    // Custom greeting banner. libunftp takes a &'static str; the banner is
    // process-lifetime config, so a one-time leak is the intended pattern.
    if let Some(greeting) = &cfg.server.greeting {
        builder = builder.greeting(Box::leak(greeting.clone().into_boxed_str()));
    }

    if let (Some(cert), Some(key)) = (cfg.server.tls_cert.clone(), cfg.server.tls_key.clone()) {
        builder = builder.ftps(cert, key);
    }

    builder
        .build()
        .context("libunftp ServerBuilder::build failed")
}

// ---------------------------------------------------------------------------
// Home directory initialisation
// ---------------------------------------------------------------------------

/// Create each camera's jail home directory so path containment (canonicalize)
/// works on the first connection. Idempotent.
pub fn ensure_home_dirs(cfg: &Config) -> std::io::Result<()> {
    for cam in &cfg.camera {
        std::fs::create_dir_all(cfg.archive.root.join(&cam.name))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Config hot-reload
// ---------------------------------------------------------------------------

/// Re-read the config file and hot-swap accounts + caps.
///
/// Fail-safe: on any error (read failure, parse error, or validation error)
/// the running config is left UNCHANGED. The new config is only applied after
/// all validation succeeds.
pub fn reload_config(
    path: &Path,
    accounts: &ArcSwap<Accounts>,
    tracker: &SessionTracker,
) -> anyhow::Result<()> {
    let cfg = crate::config::load(path).map_err(|e| anyhow::anyhow!("reload: {e}"))?;
    ensure_home_dirs(&cfg).map_err(|e| anyhow::anyhow!("reload: ensure_home_dirs: {e}"))?;
    accounts.store(Arc::new(crate::account::build(&cfg)));
    tracker.set_limits(
        cfg.limits.max_connections,
        cfg.limits.max_connections_per_account,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Async run entry point
// ---------------------------------------------------------------------------

/// Build the server from `cfg` and start listening. This is the main entry
/// point called by `src/main.rs`. It does not return until the server stops.
///
/// A background task listens for SIGHUP and calls `reload_config` on each
/// signal. On reload failure the running config is left unchanged (fail-safe).
///
/// NOTE: `drop_privileges` is NOT called here — see module-level documentation
/// for the reasoning.
pub async fn run(cfg: Config, config_path: PathBuf) -> anyhow::Result<()> {
    ensure_home_dirs(&cfg).context("failed to create camera home directories")?;
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
            let mut hup =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("cannot install SIGHUP handler: {e}");
                        return;
                    }
                };
            while hup.recv().await.is_some() {
                match reload_config(&path, &accounts, &tracker) {
                    Ok(()) => tracing::info!("config reloaded on SIGHUP"),
                    Err(e) => {
                        tracing::warn!("SIGHUP reload failed, keeping current config: {e}")
                    }
                }
            }
        });
    }

    let server = build_server(&cfg, accounts, tracker)?;
    let addr = format!("{}:{}", cfg.server.listen, cfg.server.port);
    server
        .listen(addr)
        .await
        .context("FTP server listen failed")
}

// ---------------------------------------------------------------------------
// Privilege-drop utilities
// ---------------------------------------------------------------------------

/// The resolved numeric uid and gid for a Unix user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserIds {
    pub uid: u32,
    pub gid: u32,
}

/// Look up a Unix user by name and return its uid and gid.
///
/// Returns `Err(String)` if the user does not exist or if the OS lookup fails.
pub fn resolve_user(name: &str) -> Result<UserIds, String> {
    use nix::unistd::User;
    match User::from_name(name) {
        Ok(Some(u)) => Ok(UserIds {
            uid: u.uid.as_raw(),
            gid: u.gid.as_raw(),
        }),
        Ok(None) => Err(format!("user '{name}' not found")),
        Err(e) => Err(format!("os error looking up user '{name}': {e}")),
    }
}

/// Drop privileges to the given Unix user (setgid then setuid).
///
/// # Safety note
///
/// This function is `unsafe`-free (uses nix wrappers). It MUST be called while
/// still single-threaded — after Tokio's runtime has started this is not safe.
///
/// # Limitation
///
/// `run` does NOT call this function because `Server::listen` binds the socket
/// internally and a prebound-socket handoff is not available via the public
/// libunftp 0.23 API. See module-level documentation.
pub fn drop_privileges(name: &str) -> Result<(), String> {
    use nix::unistd::{setgid, setuid, Gid, Uid};
    let ids = resolve_user(name)?;
    // setgid first — once setuid is called we may lose the ability to setgid.
    setgid(Gid::from_raw(ids.gid)).map_err(|e| format!("setgid to {} failed: {e}", ids.gid))?;
    setuid(Uid::from_raw(ids.uid)).map_err(|e| format!("setuid to {} failed: {e}", ids.uid))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;

    // -----------------------------------------------------------------------
    // resolve_user
    // -----------------------------------------------------------------------

    /// TDD: written before implementation.
    /// Every Unix system has a "root" user with uid 0.
    #[test]
    fn resolve_user_root_has_uid_0() {
        let ids = resolve_user("root").expect("root must exist");
        assert_eq!(ids.uid, 0, "root uid must be 0");
        // gid for root is also typically 0, but varies; just check it's Some.
        let _ = ids.gid; // field exists and is accessible
    }

    /// TDD: written before implementation.
    /// A clearly non-existent user must produce an Err.
    #[test]
    fn resolve_user_unknown_errors() {
        let result = resolve_user("definitely-not-a-user-xyz-9999");
        assert!(result.is_err(), "unknown user must return Err");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("not found") || msg.contains("os error"),
            "error message should mention not-found or os error, got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // build_server — assembly / compile-correctness test
    // -----------------------------------------------------------------------

    /// A minimal valid Config string. Passwords are syntactically fake — the
    /// server is built but never asked to authenticate, so hash validity is
    /// irrelevant here.
    const MINIMAL_CFG: &str = r#"
[server]
listen = "127.0.0.1"
port = 21210
passive_ports = [50000, 50010]

[archive]
root = "/tmp/reolink-test-archive"
retention_days = 7

[limits]
max_connections = 4
max_connections_per_ip = 2
new_conns_per_min_per_ip = 10
idle_timeout_secs = 30
min_transfer_rate_bytes_per_sec = 512
failed_login_lockout = { max_attempts = 3, window_secs = 60, ban_secs = 300 }

[[camera]]
name = "front-door"
upload_password_hash = "$argon2id$v=19$m=16,t=2,p=1$AAAA$AAAAAAAAAAAAAAAAAAAAAA"
"#;

    /// Proves that the full generic builder chain — including the
    /// DefaultUser stub, user_detail_provider type switch, notify_presence,
    /// passive_ports, idle_session_timeout, and failed_logins_policy —
    /// type-checks and produces a Server<ReoBackend, ReoUser>.
    /// Does NOT call `.listen()`.
    #[test]
    fn build_server_assembles_ok() {
        let cfg = parse_str(MINIMAL_CFG).expect("MINIMAL_CFG must parse");
        let accounts =
            std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(crate::account::build(&cfg)));
        let tracker = std::sync::Arc::new(crate::limits::SessionTracker::new(
            cfg.limits.max_connections,
            cfg.limits.max_connections_per_account,
        ));
        let result = build_server(&cfg, accounts, tracker);
        assert!(
            result.is_ok(),
            "build_server must return Ok for a valid Config, got: {:?}",
            result.err()
        );
    }

    // -----------------------------------------------------------------------
    // reload_config — TDD: written before implementation
    // -----------------------------------------------------------------------

    /// TDD: written before implementation.
    ///
    /// Verifies two behaviors:
    /// 1. A valid reload swaps accounts (new camera becomes visible).
    /// 2. An invalid reload (garbage TOML) returns Err and leaves accounts unchanged.
    #[test]
    fn reload_swaps_accounts_and_keeps_old_on_invalid() {
        use arc_swap::ArcSwap;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reoftpd.toml");

        // initial valid config with one camera "front-door"
        std::fs::write(&path, MINIMAL_CFG).unwrap();
        let cfg = crate::config::load(&path).unwrap();
        let accounts = std::sync::Arc::new(ArcSwap::from_pointee(crate::account::build(&cfg)));
        let tracker = std::sync::Arc::new(crate::limits::SessionTracker::new(
            cfg.limits.max_connections,
            cfg.limits.max_connections_per_account,
        ));
        assert!(accounts.load().get("front-door").is_some());
        assert!(accounts.load().get("garage").is_none());

        // valid reload that adds "garage"
        let with_garage = format!(
            "{MINIMAL_CFG}\n[[camera]]\nname = \"garage\"\nupload_password_hash = \
             \"$argon2id$v=19$m=16,t=2,p=1$AAAA$AAAAAAAAAAAAAAAAAAAAAA\"\n"
        );
        std::fs::write(&path, &with_garage).unwrap();
        reload_config(&path, &accounts, &tracker).unwrap();
        assert!(
            accounts.load().get("garage").is_some(),
            "reload should add the new camera"
        );

        // invalid reload: garbage TOML — must Err AND leave accounts unchanged
        std::fs::write(&path, "this is not valid toml [[[").unwrap();
        let before = accounts.load().get("garage").is_some();
        assert!(reload_config(&path, &accounts, &tracker).is_err());
        assert_eq!(
            accounts.load().get("garage").is_some(),
            before,
            "bad reload must not change accounts"
        );
    }
}
