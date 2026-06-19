# reoftpd — Append-Only FTP Archive for Reolink Cameras

**Status:** Design approved (brainstorming complete)
**Date:** 2026-06-18
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
incriminates them.

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

- **Engine:** `pyftpdlib` (MIT, pure Python) — provides a per-user authorizer
  with granular permission flags, per-user chroot jailing, and FTPS/TLS.
- **TLS:** `pyOpenSSL` (required by pyftpdlib for FTPS).
- **Password hashing:** `argon2-cffi` (argon2id) when available, with a
  stdlib **PBKDF2-HMAC-SHA256** fallback (see §7).
- **Config parsing:** stdlib `tomllib` (Python 3.11+) with `tomli` fallback on
  3.8–3.10.

Pure-Python core so the daemon installs on any Unix with Python 3.8+
(Linux, *BSD, macOS).

### Alternatives rejected
- **Harden vsftpd directly** — solid, but its config cannot reject *overwrites*
  (only whole commands via `cmds_denied`), and per-camera foldering + retention
  + scoped read accounts would be bolted-on scripts. Less cohesive, less
  portable.
- **Raw-socket FTP server from scratch** — re-implementing FTP + TLS securely
  is a large attack surface to audit for no gain over pyftpdlib.

## 4. Account & Access Model

The config file `reoftpd.toml` is the **single source of truth**. No separate
user database.

### 4.1 Upload accounts (cameras) — one per camera
- Exactly one password per camera. Append-only. Jailed to the camera's folder.
- Permission set `e l m w` (cwd, list, mkdir, store). Withholds
  `a d f r M T` (no append-to-existing, delete, rename, **read**, chmod, mtime).
- Plus the no-overwrite `STOR` override (§5).

### 4.2 Viewer accounts (readers) — separate and explicit
- Independent accounts; **not** bound to a camera. Created only as needed.
- Permission set `e l r` (cwd, list, retrieve). Strictly read-only.
- Each viewer has a `scope`: `"all"`, a single camera, or a list mixing camera
  names and group names.

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
| `STOR` | allowed via the `w` permission, then gated by the rules below |
| `STOU` | allowed via `w` (server picks a unique name); same rules applied |
| `APPE` | **denied** — the `a` flag is withheld, so pyftpdlib rejects it before any filesystem call (Reolink never uses it; resume is handled via `STOR`+`REST`) |
| `REST <n>` | accepted only as a transfer offset that satisfies the non-overlap rule below; otherwise the following store is rejected |

Note: "append-only" names the *archive* property (it only grows). It does
**not** mean the FTP `APPE` command is permitted — `APPE` mutates a file in
place and is denied.

### 5.2 Permission set (layer 1)

The authorizer grants uploaders exactly `e l m w` (cwd, list, mkdir, store) and
withholds `a d f r M T`. pyftpdlib rejects the withheld commands — including
`APPE`, `DELE`, `RMD`, `RNFR/RNTO`, `RETR` — before any filesystem call.

### 5.3 Non-overlap rule (layer 2)

`handler.py` computes the **start offset** of each store:

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
3. When the data connection closes successfully, the server **atomically
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
offset; across transfers it is the start offset of each subsequent store. Both
candidate engines expose the offset at store time, so §5.3 is enforceable:

- **`libunftp` (Rust):** the storage backend's `put(user, input, path,
  start_pos: u64)` receives the offset as `start_pos`. The backend `stat`s the
  staging target and enforces `start_pos == existing_size`. A **negative offset
  is impossible** — `start_pos` is `u64` and libunftp's `REST` parser rejects a
  non-numeric/negative argument before `put` is called.
- **`pyftpdlib` (Python):** the offset is `self._restart_position`, readable in
  the `ftp_STOR` override; `ftp_REST` already rejects negatives at the protocol
  layer (`501 Invalid parameter`).

Regardless of engine the handler also:

1. **Re-validates the offset defensively** — rejects any offset that is
   negative or not a whole number, independent of the engine's own parsing.
2. **Blocks cumulative overlap across cycles** — every `REST`+`STOR` cycle
   re-checks `start == current size`; once a file is finalized (§5.4) it is
   frozen and refuses writes at any offset.
3. **Locks the transfer mode** — forces `MODE S` (stream) + `STRU F` (file) and
   rejects `MODE B`/`MODE C` (block/compressed) and `STRU R`/`P` (record/page),
   which carry their own restart markers and could express discontiguous
   writes. (Both engines already restrict to stream/file; this makes the
   guarantee explicit.)

## 6. Read Scoping — `ScopedReadOnlyFS`

A subclass of pyftpdlib's `AbstractedFS` delivers viewer scopes:

- `scope = "all"` → simple jail at `[archive].root`.
- `scope = ["one-camera"]` → simple jail at that camera's dir.
- `scope` spanning multiple cameras/groups → a **synthesized virtual root**:
  listing `/` shows only the allowed camera names; `/<cam>/...` maps to the
  real directory; `validpath` asserts every resolved real path stays inside one
  of the allowed roots. `../` traversal is blocked by the realpath check;
  symlinks are rejected because realpath would resolve them outside the allowed
  roots. Read-only is doubly guaranteed — by the `e l r` permission set and by
  the FS exposing no write operations.

## 7. Password Hashing

- **Default:** argon2id via `argon2-cffi`, OWASP parameters
  (`m=19456 KiB, t=2, p=1`). Output is a self-describing PHC string
  (`$argon2id$v=19$...`).
- **Fallback:** stdlib PBKDF2-HMAC-SHA256, stored as a self-describing string
  (`pbkdf2_sha256$<iters>$<salt>$<hash>`). Used where `argon2-cffi` cannot be
  installed (e.g. exotic *BSD without a C toolchain).
- **Verification** auto-selects the verifier by the stored string's prefix, so
  a deployment can mix hash types. `reoftpd hash-password` emits argon2id
  whenever the library is present.

Rationale for argon2id over argon2i: argon2i is side-channel-hardened but
weaker against GPU/ASIC and time-memory trade-off attacks — exactly the
offline cracking risk if the config/backup leaks. argon2id is the hybrid
recommended by RFC 9106 and OWASP for password storage.

## 8. Transport Security

- **Opportunistic FTPS.** If `tls_cert`/`tls_key` are configured, the server
  advertises `AUTH TLS` and uses it when the camera offers it, falling back to
  plain FTP otherwise.
- **Per-account `require_tls = true`** forces TLS for cameras (and viewers)
  that support it; a non-TLS login for such an account is rejected after
  authentication.
- `reoftpd gencert` produces a self-signed cert. The passive-port range is
  configurable and must be opened in the firewall (documented).

## 9. Foldering

Trust the camera's path, sandboxed. Each camera authenticates into its own
jailed home (`[archive].root/<name>/`) and creates its native `<...>/<date>/`
tree via `MKD`. The server does not rewrite paths. The jail guarantees the
camera cannot escape its home even with `../`.

## 10. Reolink Test-File Handling

On "Test", Reolink uploads a probe file, often repeatedly, which strict
append-only would reject and surface as "FTP test failed". The handler detects
Reolink's test-filename pattern and routes those writes to a per-camera
`.quarantine/` area where overwrite **is** allowed, so the camera's Test
button succeeds. Quarantined files are excluded from the archive and cleaned
aggressively (short TTL). Real captures remain strictly append-only.

## 11. Retention

`retention.py` is a separate trusted process — **not** reachable over FTP, so
append-only never blocks legitimate cleanup.

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

- **systemd (recommended):** `AmbientCapabilities=CAP_NET_BIND_SERVICE` +
  `User=reoftpd` so the daemon never runs as root, plus `NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, a read-only filesystem
  except the archive dir, and syscall filtering.
- **portable:** start as root only to `bind()`, then immediately `setuid` to a
  dedicated unprivileged user before serving.

## 13. Logging & Observability

Structured logs to stdout/journald: authentications (success/fail), every
upload, and — importantly — every **rejected delete/overwrite/rename attempt**
with the username and path. Makes tamper attempts auditable and is
fail2ban-friendly for brute-force lockout.

## 14. Package Layout

```
reoftpd/
  __init__.py
  config.py       load + validate TOML; expand groups; build account objects
  authorizer.py   hashed-password authorizer; per-user perms; require_tls
  handler.py      FTPHandler subclass: no-overwrite STOR, test-file quarantine,
                  logging hooks
  fs.py           ScopedReadOnlyFS (multi-root virtual filesystem for viewers)
  hashing.py      argon2id + pbkdf2 hashing/verification, PHC-style strings
  server.py       wire TLS, bind, drop privileges, SIGHUP reload, signals, run
  retention.py    age-based sweep
  cli.py          serve | cleanup | add-camera | add-viewer | hash-password |
                  gencert
config/reoftpd.example.toml
packaging/
  reoftpd.service
  reoftpd-cleanup.service
  reoftpd-cleanup.timer
tests/
pyproject.toml
```

## 15. CLI

- `reoftpd serve [--config PATH]`
- `reoftpd cleanup [--once] [--dry-run] [--config PATH]`
- `reoftpd add-camera <name> [--username U] [--require-tls]` — prompts for
  password, appends a hashed `[[camera]]` entry.
- `reoftpd add-viewer <name> --scope all|cam,grp,...` — appends a hashed
  `[[viewer]]` entry.
- `reoftpd hash-password` — emit an argon2id (or pbkdf2 fallback) hash.
- `reoftpd gencert` — self-signed cert/key for FTPS.
- `SIGHUP` reloads accounts without dropping live transfers.

## 16. Testing (TDD)

Unit tests:
- non-overlap rule: `start == existing` permitted; `start < existing` (overlap)
  and `start > existing` (gap) rejected; new-file requires offset 0
- `REST`-driven resume of a staging file extends without overlap
- stage-then-finalize: atomic rename on success; any store to a finalized name
  refused at any offset (completed-file immutability)
- `STOU` subjected to the same rules; `APPE` denied by permission
- violation handling: `550` + tamper log + staging data discarded
- uploader vs viewer permission sets
- argon2id + pbkdf2 hashing/verification and prefix auto-selection
- test-file quarantine routing
- jail escape attempts (`../`, symlinks) for both single-root and
  `ScopedReadOnlyFS`
- retention age calculation and empty-dir pruning
- config loading, group expansion, name/username defaulting, scope validation

Integration test: spin up the server on a high port and drive it with a real
FTP client to confirm:
- `STOR` of a new file succeeds and is finalized atomically
- `STOR` onto a finalized name is refused (no overwrite, no tail-append)
- `REST`+`STOR` resuming an interrupted upload succeeds; `REST` into existing
  bytes is refused
- `DELE`, `RMD`, `RNFR/RNTO`, `RETR`, `APPE` are refused for an uploader
- a viewer can `RETR`/`LIST` within scope and cannot reach out-of-scope cameras
- a viewer cannot `STOR`/`DELE`

## 17. Dependencies

`pyftpdlib`, `pyOpenSSL`, `argon2-cffi` (optional but default), `tomli`
(only on Python < 3.11). Deliberately small surface.
