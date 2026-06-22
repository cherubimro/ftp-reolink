# Connection Caps — Design

**Status:** Approved (brainstorming complete)
**Date:** 2026-06-22
**Author:** alin.anton
**Extends:** the reoftpd append-only FTP archive (see 2026-06-18-reoftpd-design.md)

## 1. Purpose

Enforce connection/session limits to blunt resource-exhaustion abuse. libunftp
0.23 exposes no accept-time veto and no peer IP at disconnect, so a true per-IP
*connection* cap cannot be enforced inside the FTP process. This design wires
what IS enforceable in-process — **global and per-account concurrent-session
caps** — and generates **nftables** rules from the same config for real per-IP
caps at the kernel (the correct layer for connection-flood defense).

## 2. Constraints discovered in libunftp 0.23

- `Server::listen()` owns the accept loop; `PreboundListener` is `pub(super)`.
- The only public connection hooks are `PresenceListener`/`DataListener`, which
  are **observe-only** (return value ignored) and fire **after** login.
- `PresenceEvent` is `LoggedIn` / `LoggedOut`; `EventMeta` carries
  `{ username, trace_id, sequence_number }` — **no source IP**.
- The peer IP is available **only** in `Credentials.source_ip` inside the
  `Authenticator`.

Therefore: login sees the IP but not a logout signal; logout sees the username
but not the IP. Per-IP in-process enforcement is infeasible; per-account
(username) and global are.

## 3. In-process concurrent-session caps

### 3.1 `SessionTracker` (replaces `ConnTracker`)
Holds live counts of active logged-in sessions:
- `global: usize`
- `per_account: HashMap<String /*username*/, usize>`
- Config: `max_global: u32` (from `limits.max_connections`),
  `max_per_account: Option<u32>` (from `limits.max_connections_per_account`;
  `None` = unlimited).

Methods (interior-mutable, `Arc`-shared, `Clone`):
- `on_login(username: &str)` — increment global and `per_account[username]`.
- `on_logout(username: &str)` — **saturating** decrement of both; remove the
  per-account entry at zero (bounded map).
- `at_capacity(username: &str) -> bool` — true if `global >= max_global` OR
  (`max_per_account` set AND `per_account[username] >= max_per_account`).

`ConnTracker`/`ConnGuard` and their tests are **removed** (per-IP in-process is
confirmed infeasible; nftables covers per-IP).

### 3.2 Accountant — `presence::ReoPresenceListener`
New module `src/presence.rs`. Implements `unftp_core` `PresenceListener`,
holding `Arc<SessionTracker>`:
- `LoggedIn` → `tracker.on_login(meta.username)`
- `LoggedOut` → `tracker.on_logout(meta.username)`
Registered via `ServerBuilder::notify_presence(...)`.

### 3.3 Gate — `ReoAuth`
`ReoAuth` gains `sessions: Arc<SessionTracker>`. In `authenticate`, AFTER
verifying the password and `require_tls`, if `sessions.at_capacity(username)`
return `AuthenticationError::new("connection limit reached")` instead of a
`Principal`. The new session is never admitted.

### 3.4 Semantics & honest caveats (documented)
- With cap N, the (N+1)th concurrent session is refused at login.
- The count is incremented at `LoggedIn` (just after the auth check), so two
  logins racing can briefly over-admit by a small margin. Acceptable.
- Decrements rely on `LoggedOut`, which libunftp fires on control-loop exit;
  saturating decrements guard against any missed event causing underflow.
- These are caps on *authenticated sessions*, applied at login — a flood of
  TCP connections that never authenticate is bounded by `idle_session_timeout`
  and by the nftables per-IP rule, not by these counters.

## 4. nftables generator

`render_nftables(cfg: &Config) -> String` — pure, testable. Emits an `inet`
table that, on the control port (`server.port`) and the passive range
(`server.passive_ports`), drops new connections exceeding
`limits.max_connections_per_ip` per source IP (`ct count over` keyed by
`ip saddr`) AND a global `ct count over limits.max_connections` on the control
port (a kernel-level backstop to the in-process global session cap). CLI subcommand
`reoftpd nftables [--config PATH]` prints it to stdout for the admin to apply
with `nft -f -` (no auto-apply, no root needed). README documents this as the
per-IP enforcement layer and that `max_connections_per_ip` is consumed here,
not in the FTP process.

## 5. Config changes

`LimitsCfg`:
- ADD `max_connections_per_account: Option<u32>` (absent = unlimited).
- `max_connections` — unchanged name; now documented as the **global
  concurrent-session** cap (in-process).
- `max_connections_per_ip` — unchanged; re-documented as **firewall-only**
  (consumed by `render_nftables`, not the FTP process).

Update `config/reoftpd.example.toml` and `README.md` accordingly (correct the
"not yet enforced" list: `max_connections` and `max_connections_per_account`
are now enforced in-process; `max_connections_per_ip` via the generated
nftables rules; `new_conns_per_min_per_ip` and `min_transfer_rate_bytes_per_sec`
remain unwired).

## 6. Server wiring

`build_server` constructs `Arc<SessionTracker>` from `cfg.limits`, injects it
into `ReoAuth { sessions, .. }`, and registers
`ReoPresenceListener { tracker }` via `.notify_presence(...)`.

## 7. Testing

Unit:
- `SessionTracker`: global cap reached → `at_capacity` true; per-account cap;
  `on_login`/`on_logout` inc/dec; saturating dec below zero; map entry removed
  at zero; `max_per_account = None` → never per-account-capped.
- `ReoAuth`: with a tracker pre-loaded to the global cap, `authenticate` with a
  VALID credential returns `Err` (capacity), and with the tracker below cap
  returns `Ok`.
- `render_nftables`: output contains the control port, the passive range, the
  per-IP count, and (if emitted) the global count.

Integration (extend `tests/integration.rs`): start the server with
`max_connections = 1`; open one session and confirm it's logged in (e.g. `pwd`);
then a second login attempt is **refused**. Close the first; a new login then
succeeds (confirms `LoggedOut` decrement).

## 8. Out of scope (unchanged from prior limitations)
Per-IP in-process caps; `new_conns_per_min_per_ip`; `min_transfer_rate`;
auto-applying nftables; SIGHUP reload.
