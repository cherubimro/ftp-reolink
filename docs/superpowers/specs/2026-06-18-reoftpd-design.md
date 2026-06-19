# reoftpd — Append-Only FTP Archive for Reolink Cameras

**Status:** Design approved (brainstorming complete)
**Date:** 2026-06-18 (revised 2026-06-19: engine = Rust/libunftp)
**Author:** alin.anton

## 1. Purpose

A small, hardened FTP server daemon that receives video clips and snapshots
from Reolink cameras and stores them in an **append-only** archive. A client
authenticated as a camera can create new files and directories but can never
read, overwrite, rename, or delete anything. Footage is reviewed through
**separate read-only accounts**. Files older than a configurable age (default
30 days) are pruned by a trusted server-side sweep that runs outside the FTP
path.

## 2. Threat Model

**Primary adversary:** someone who physically steals a camera, extracts its
stored FTP credentials, and connects to the server to destroy the footage that
incriminates them. A secondary adversary floods the server with connections to
deny service.

**Guarantee:** with a camera's credentials a client can **only create new files
and directories**. The server refuses — at the protocol level — every command
that could delete, overwrite, rename, or read back existing data
(`DELE`, `RMD`, `RNFR`/`RNTO`, `RETR`, and `STOR` onto an existing path). Each
camera is jailed to its own home directory and cannot see or reach any other
camera's folder.

**Separation of duties:** upload and read are distinct credentials with
disjoint, non-overlapping permissions.

- A stolen **camera** credential → can blindly append to that one camera's
  folder; cannot read *any* footage, cannot tamper, cannot reach other cameras.
- A leaked **viewer** credential → can read footage in its scope
  (confidentiality loss) but **cannot tamper** — archive integrity is
  preserved.

Confidentiality and integrity therefore fail independently.

**Out of scope (explicitly):** an attacker with shell/root on the server, or
physical access to the disks. Retention deletion is a trusted server-side
process deliberately outside the FTP path.

## 3. Technology Choice

**Language: Rust.** Chosen for C-class performance and a small, self-contained
static binary *without* the memory-safety vulnerability class that dominates
the historic FTP-server CVE record. The risky parts (FTP protocol parsing, TLS)
are delegated to vetted, memory-safe crates rather than hand-written.

- **FTP engine:** [`libunftp`](https://crates.io/crates/libunftp) — an async
  (tokio) FTPS server library with a pluggable `Authenticator` and a pluggable
  `StorageBackend`. We implement a **custom storage backend** (append-only
  semantics, scoped reads) and a **custom authenticator** (argon2id accounts).
  The library owns the FTP protocol; we own policy.
- **TLS:** `rustls` (pure-Rust, memory-safe; no OpenSSL) via libunftp's FTPS
  feature.
- **Async runtime:** `tokio` (event-driven `epoll`/`kqueue` — scales to many
  idle connections cheaply; see §14, Abuse/DoS resistance).
- **Password hashing:** the pure-Rust `argon2` + `password-hash` crates
  (argon2id, PHC strings). Pure Rust → no C toolchain needed (see §7).
- **Config:** `serde` + `toml`.
- **CLI:** `clap`. **Logging:** `tracing` (+ optional journald).
- **Self-signed cert generation:** `rcgen` (pure Rust).
- **Privilege drop / sandbox:** `nix` (setuid/setgid/chroot); optional
  Landlock (Linux) / Capsicum (FreeBSD) as defense-in-depth.

### Build & portability
Targets are built per-OS (no runtime needed): Linux (`x86_64`/`aarch64`,
musl for a fully-static binary) and **FreeBSD** (`x86_64-unknown-freebsd`,
`aarch64-unknown-freebsd` — Tier 2). On FreeBSD a self-contained binary is
produced; full `crt-static` is available, but because FreeBSD discourages
static libc and all our crypto is pure Rust (`rustls`, `argon2`) and the daemon
does no outbound name resolution, a "mostly-static" binary (static except
base-system libc) is the pragmatic default and still ships with zero
third-party shared-object dependencies.

### Alternatives rejected
- **Python / `pyftpdlib`** — fully viable and was the original plan; dropped in
  favour of a small static native binary with no runtime dependency.
- **Hand-rolled FTP over raw sockets (thread-per-connection)** — rejected on two
  grounds: (1) the camera fixes the wire protocol to FTP/FTPS, so a from-scratch
  implementation must faithfully reproduce the *entire* FTP spec (control/data
  channels, `PORT`/`PASV`/`EPSV`/`EPRT`, `AUTH TLS`/`PBSZ`/`PROT`, `REST`,
  Telnet `IAC`) — all the complexity, none of the freedom; (2) thread-per-
  connection is the classic connection-exhaustion (Slowloris) DoS target —
  *worse* under flood than async I/O, not better. The async engine plus the §14
  controls give strictly better DoS posture at a fraction of the attack surface.
- **Harden vsftpd directly** — its config cannot express byte-level append-only,
  scoped read accounts, or stage-then-finalize; those would be bolted-on scripts.

## 4. Account & Access Model

The config file `reoftpd.toml` is the **single source of truth**. No separate
user database. The authenticator yields a `User { role, scope, require_tls }`
that the storage backend consults to authorize every operation.

### 4.1 Upload accounts (cameras) — one per camera
- Exactly one password per camera. Append-only. Jailed to the camera's folder.
- **Allowed capabilities:** make directory (`MKD`), store a *new* file
  (`STOR`/`STOU`), list/cwd.
- **Denied:** retrieve (`RETR`), delete (`DELE`/`RMD`), rename (`RNFR`/`RNTO`),
  append/overwrite (`APPE`, or `STOR` onto existing).
- Enforced in the storage backend (denied ops return *permission denied* for
  `role == Uploader`) plus the byte-level rules of §5.

### 4.2 Viewer accounts (readers) — separate and explicit
- Independent accounts; **not** bound to a camera. Created only as needed.
- **Allowed capabilities:** list (`LIST`/`NLST`/`MLSD`), retrieve (`RETR`), cwd.
- **Denied:** every write (`STOR`/`STOU`/`APPE`/`DELE`/`RMD`/`MKD`/rename).
- Each viewer has a `scope`: `"all"`, a single camera, or a list mixing camera
  names and group names (§6).

### 4.3 Groups
- Pure sugar: a named list of camera names, expanded at config load. Not a
  first-class entity.

### 4.4 Name vs username (cameras)
- **`name`** — stable internal identity: the folder name in the archive, the
  token viewers reference in `scope`, the label in logs. Never changes
  (renaming would orphan data).
- **`username`** — the FTP login the camera sends. **Defaults to `name`**,
  overridable to decouple login from folder name (rename logins without moving
  data; non-obvious logins).

### 4.5 Example config

```toml
[server]
listen = "0.0.0.0"
port = 21
passive_ports = [50000, 50100]
tls_cert = "/etc/reoftpd/cert.pem"   # optional; enables opportunistic FTPS
tls_key  = "/etc/reoftpd/key.pem"

[archive]
root = "/srv/reolink"
retention_days = 30

[limits]                              # see §14 (Abuse / DoS resistance)
max_connections = 256
max_connections_per_ip = 8
new_conns_per_min_per_ip = 30
idle_timeout_secs = 120
min_transfer_rate_bytes_per_sec = 1024
failed_login_lockout = { max_attempts = 5, window_secs = 300, ban_secs = 900 }

# --- upload identities: one per camera, append-only ---
[[camera]]
name = "front-door"
username = "cam-fd-7q2"              # optional; defaults to name
upload_password_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."
require_tls = true

[[camera]]
name = "driveway"
upload_password_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."

# --- named groups: sugar for a list of camera names ---
[group]
outdoor = ["driveway", "back-yard", "side-gate"]

# --- read identities: read-only, scoped ---
[[viewer]]
name = "admin"
password_hash = "$argon2id$v=19$..."
scope = "all"

[[viewer]]
name = "patio-review"
password_hash = "$argon2id$v=19$..."
scope = ["outdoor", "front-door"]   # group + camera names, deduped
```

## 5. Append-Only Enforcement

Append-only is enforced at the **byte level**: a write may only extend a file
at its current end, never land on bytes that already exist, and a *completed*
file is frozen immutable.

### 5.1 The write surface

Every FTP command that can place bytes on disk must be policed, not just
`STOR`:

| Command | Disposition |
|---|---|
| `STOR` | allowed for uploaders, then gated by the rules below |
| `STOU` | allowed (server picks a unique name); same rules applied |
| `APPE` | **denied** by the backend for uploaders (Reolink never uses it; resume is handled via `STOR`+`REST`) |
| `REST <n>` | accepted only as a transfer offset that satisfies the non-overlap rule below; otherwise the following store is rejected |

Note: "append-only" names the *archive* property (it only grows). It does
**not** mean the FTP `APPE` command is permitted — `APPE` mutates a file in
place and is denied.

### 5.2 Capability gate (layer 1)

The storage backend authorizes each operation against the authenticated user's
role **before touching the filesystem**. An uploader role permits only
`MKD` + store-of-a-new-file + list/cwd; a viewer role permits only list +
`RETR` + cwd. Every other operation returns *permission denied* (`550`). This
is the libunftp analogue of a permission-flag set, but enforced in our code so
it is explicit and unit-testable.

### 5.3 Non-overlap rule (layer 2)

The backend's `put` computes the **start offset** of each store:

- `REST <n>` before the transfer → `start = n`
- plain `STOR`/`STOU` → `start = 0`

Let `existing` = the current size of the staging target (0 if absent). The
store is permitted **only if `start == existing`**:

- `start < existing` → would **overlap existing bytes** → reject `550`.
- `start > existing` → would leave a sparse **gap** → reject `550`.
- new file → `existing == 0`, so only `start == 0` is allowed.

This permits resuming a dropped upload (re-`STOR` with `REST == partial size`)
while making it impossible to rewrite any byte already stored.

### 5.4 Stage-then-finalize (completed-file immutability)

To stop a client appending bytes to the *end* of an already-finished clip,
completed files are frozen:

1. Each upload streams to an internal **staging file** (e.g.
   `<final>.reoftpd-partial` in the target dir, hidden from listings).
2. The non-overlap rule (§5.3) is enforced against the staging file's current
   size, so resume extends the staging file and never overlaps.
3. When the data connection closes successfully, the backend **atomically
   renames** the staging file to the final name and freezes it.
4. Any subsequent store targeting an **already-finalized name is refused**
   (any offset) — completed clips are immutable.

Because Reolink uses fresh timestamped filenames and whole-file `STOR`, this is
invisible to the camera.

### 5.5 Violation handling

On any violation (overlap, gap, or a write to a finalized file), the server:

1. Refuses with `550`.
2. **Logs a tamper event** with username, path, attempted offset, and existing
   size.
3. **Discards** the partial staging data produced by that attempt, leaving no
   half-written residue.

### 5.6 Offset validation & transfer-mode lock-down

In FTP **stream mode** a store is one contiguous byte stream beginning at the
restart offset, so the only overlap vector inside a transfer is that start
offset; across transfers it is the start offset of each subsequent store.
libunftp exposes the offset at store time, so §5.3 is enforceable:

- The storage backend's `put(user, input, path, start_pos: u64)` receives the
  offset as `start_pos`. The backend `stat`s the staging target and enforces
  `start_pos == existing_size`. A **negative offset is impossible** —
  `start_pos` is `u64` and libunftp's `REST` parser rejects a non-numeric or
  negative argument before `put` is ever called.

The backend additionally:

1. **Re-validates the offset defensively** — treats anything other than a whole
   number in `[0, existing_size]` as a violation, independent of the engine.
2. **Blocks cumulative overlap across cycles** — every `REST`+`STOR` cycle
   re-checks `start == current size`; once a file is finalized (§5.4) it is
   frozen and refuses writes at any offset.
3. **Locks the transfer mode** — forces `MODE S` (stream) + `STRU F` (file) and
   rejects `MODE B`/`MODE C` (block/compressed) and `STRU R`/`P` (record/page),
   which carry their own restart markers and could express discontiguous
   writes. (libunftp restricts to stream/file already; this makes the guarantee
   explicit.)

## 6. Read Scoping

Viewer scopes are delivered inside the storage backend, which receives the
authenticated `User` (carrying `scope`) on every call and maps the requested
virtual path against the allowed roots:

- `scope = "all"` → backend rooted at `[archive].root`.
- `scope = ["one-camera"]` → backend rooted at that camera's dir.
- `scope` spanning multiple cameras/groups → a **synthesized virtual root**:
  listing `/` shows only the allowed camera names; `/<cam>/...` maps to the real
  directory. Every resolved real path is canonicalized and asserted to stay
  inside one of the allowed roots — `../` traversal and symlink escape both fail
  the containment check. Read-only is doubly guaranteed: the capability gate
  (§5.2) denies writes for viewers, and the read backend exposes no write ops.

## 7. Password Hashing

- **Algorithm:** argon2id via the pure-Rust `argon2` crate, OWASP parameters
  (`m = 19456 KiB, t = 2, p = 1`). Output is a self-describing PHC string
  (`$argon2id$v=19$...`) via the `password-hash` crate.
- Pure Rust means **no C toolchain and no OpenSSL** — it builds wherever Rust
  builds, including the FreeBSD static target.
- Verification parses the PHC string, so parameters can be tuned over time and
  old and new hashes coexist. `reoftpd hash-password` emits argon2id.

Rationale for argon2id over argon2i: argon2i is side-channel-hardened but
weaker against GPU/ASIC and time-memory trade-off attacks — exactly the
offline cracking risk if the config/backup leaks. argon2id is the hybrid
recommended by RFC 9106 and OWASP for password storage.

## 8. Transport Security

- **Opportunistic FTPS.** If `tls_cert`/`tls_key` are configured, the server
  advertises `AUTH TLS` (rustls) and uses it when the camera offers it, falling
  back to plain FTP otherwise.
- **Per-account `require_tls = true`** forces TLS for cameras (and viewers)
  that support it; a login on a non-secured control channel for such an account
  is rejected.
- `reoftpd gencert` produces a self-signed cert/key via `rcgen`. The
  passive-port range is configurable and must be opened in the firewall
  (documented).

## 9. Foldering

Trust the camera's path, sandboxed. Each camera authenticates into its own
jailed home (`[archive].root/<name>/`) and creates its native `<...>/<date>/`
tree via `MKD`. The server does not rewrite paths. The jail guarantees the
camera cannot escape its home even with `../`.

## 10. Reolink Test-File Handling

On "Test", Reolink uploads a probe file, often repeatedly, which strict
append-only would reject and surface as "FTP test failed". The backend detects
Reolink's test-filename pattern and routes those writes to a per-camera
`.quarantine/` area where overwrite **is** allowed, so the camera's Test
button succeeds. Quarantined files are excluded from the archive and cleaned
aggressively (short TTL). Real captures remain strictly append-only.

## 11. Retention

The `reoftpd cleanup` subcommand is a separate trusted process — **not**
reachable over FTP, so append-only never blocks legitimate cleanup.

- Deletes files whose mtime exceeds `retention_days` (default 30).
- Prunes emptied directories.
- Cleans `.quarantine/` on a short TTL.
- Cleans **orphaned staging files** (`*.reoftpd-partial`) abandoned by
  interrupted uploads after a short TTL.
- Logs every deletion. Supports `--dry-run`.
- Shipped as a `systemd` timer (daily); on non-systemd hosts run
  `reoftpd cleanup --once` from cron.

## 12. Privilege Model

FTP requires the privileged port 21. Two supported modes:

- **systemd (recommended, Linux):** `AmbientCapabilities=CAP_NET_BIND_SERVICE` +
  `User=reoftpd` so the daemon never runs as root, plus `NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, a read-only filesystem
  except the archive dir, and syscall filtering.
- **portable:** start as root only to `bind()`, then immediately drop to a
  dedicated unprivileged user (`setgid`/`setuid` via `nix`) before serving.

Optional defense-in-depth: Landlock (Linux) or Capsicum (FreeBSD) to confine
the process to the archive directory at the kernel level.

## 13. Logging & Observability

Structured logs via `tracing` to stdout/journald: authentications
(success/fail), every upload, and — importantly — every **rejected
delete/overwrite/rename attempt** and every **DoS-control trip** (limit hit,
lockout) with the username/IP and path. Makes tamper and abuse attempts
auditable and is fail2ban-friendly.

## 14. Abuse / DoS Resistance

Resistance comes from an **async (event-driven) core plus explicit policy
limits** — never from a thread-per-connection model, which is itself the
classic connection-exhaustion target. tokio holds many idle connections
cheaply; the following controls (configured under `[limits]`, §4.5) stop a
client from exhausting resources:

- **Global connection cap** (`max_connections`) — a bounded concurrency
  semaphore; connections beyond the cap are refused immediately.
- **Per-IP connection cap** (`max_connections_per_ip`) — one flooding source
  cannot consume all slots.
- **Per-IP new-connection rate limit** (`new_conns_per_min_per_ip`) — token
  bucket; throttles connection storms.
- **Idle-session timeout** (`idle_timeout_secs`) — closes silent control
  connections; libunftp's `idle_session_timeout`.
- **Minimum-transfer-rate timeout** (`min_transfer_rate_bytes_per_sec`) — drops
  Slowloris-style data connections that dribble bytes to hold resources.
- **Failed-login lockout** (`failed_login_lockout`) — temp-ban an IP/account
  after N failures in a window (libunftp `FailedLoginsPolicy` + our accounting),
  blunting credential brute-force.
- **Bounded command/line length** — reject oversized control lines so a single
  connection cannot balloon memory.
- **Defence in depth outside the process:** kernel SYN cookies; `nftables`
  connection-rate limiting; and the strongest mitigation — **do not expose FTP
  to the public internet**: bind to a LAN/VPN interface. Documented in
  deployment notes.

These are policy controls independent of the threading model and give strictly
better flood resistance than a hand-rolled threaded server.

## 15. Package Layout (Rust crate)

```
reoftpd/
  Cargo.toml
  src/
    main.rs          CLI dispatch (clap): serve | cleanup | add-camera |
                     add-viewer | hash-password | gencert
    config.rs        load + validate TOML (serde); expand groups; account model
    auth.rs          Authenticator: argon2id verify; build User{role,scope,tls}
    backend.rs       StorageBackend: capability gate, append-only put
                     (non-overlap + stage-finalize), scoped read view,
                     test-file quarantine
    hashing.rs       argon2id hashing/verification (PHC strings)
    tls.rs           rustls config; gencert via rcgen
    limits.rs        connection caps, per-IP rate limiting, timeouts (§14)
    retention.rs     age-based sweep
    server.rs        build libunftp Server, bind, privilege drop, SIGHUP
                     reload, signals, run loop
  config/reoftpd.example.toml
  packaging/
    reoftpd.service
    reoftpd-cleanup.service
    reoftpd-cleanup.timer
  tests/
    integration.rs   drives the server with a real FTP client crate
```

## 16. CLI

- `reoftpd serve [--config PATH]`
- `reoftpd cleanup [--once] [--dry-run] [--config PATH]`
- `reoftpd add-camera <name> [--username U] [--require-tls]` — prompts for
  password, appends a hashed `[[camera]]` entry.
- `reoftpd add-viewer <name> --scope all|cam,grp,...` — appends a hashed
  `[[viewer]]` entry.
- `reoftpd hash-password` — emit an argon2id PHC hash.
- `reoftpd gencert` — self-signed cert/key for FTPS.
- `SIGHUP` reloads accounts without dropping live transfers.

## 17. Testing (TDD)

Unit tests (`cargo test`):
- non-overlap rule: `start == existing` permitted; `start < existing` (overlap)
  and `start > existing` (gap) rejected; new-file requires offset 0
- `REST`-driven resume of a staging file extends without overlap
- stage-then-finalize: atomic rename on success; any store to a finalized name
  refused at any offset (completed-file immutability)
- `STOU` subjected to the same rules; `APPE` denied for uploaders
- violation handling: `550` + tamper log + staging data discarded
- capability gate: uploader vs viewer allowed/denied operation matrix
- argon2id hashing/verification round-trip and PHC parsing
- test-file quarantine routing
- jail escape attempts (`../`, symlinks) for single-root and scoped views
- retention age calculation and empty-dir pruning
- config loading, group expansion, name/username defaulting, scope validation
- limits: per-IP cap, global cap, rate-limit token bucket, lockout accounting

Integration test (`tests/integration.rs`): bind the server on a high port and
drive it with a real FTP client crate to confirm:
- `STOR` of a new file succeeds and is finalized atomically
- `STOR` onto a finalized name is refused (no overwrite, no tail-append)
- `REST`+`STOR` resuming an interrupted upload succeeds; `REST` into existing
  bytes is refused
- `DELE`, `RMD`, `RNFR/RNTO`, `RETR`, `APPE` are refused for an uploader
- a viewer can `RETR`/`LIST` within scope and cannot reach out-of-scope cameras
- a viewer cannot `STOR`/`DELE`
- connection caps and idle timeout fire as configured

## 18. Dependencies (crates)

`libunftp` (FTPS engine), `rustls` (TLS, via libunftp ftps feature), `tokio`
(runtime), `argon2` + `password-hash` (hashing), `serde` + `toml` (config),
`clap` (CLI), `tracing` + `tracing-subscriber` (logging), `nix` (privilege
drop), `rcgen` (self-signed certs), `governor` (rate limiting). Test-only: an
FTP client crate (e.g. `suppaftp`). Deliberately small, memory-safe surface.
