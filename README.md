# reoftpd — append-only FTPS archive for Reolink cameras

`reoftpd` is a hardened FTP server that lets Reolink cameras push footage to a
local NAS or server while preventing them from reading, overwriting, deleting,
or renaming any file they have uploaded.  Separate read-only viewer accounts
let authorised users browse and download footage without gaining any write
access.

## Security guarantees

- **Append-only uploads**: cameras can only create new files.  Overwrite,
  delete, rename, and any form of read are refused at the protocol level.
- **Byte-level non-overlap**: a second STOR to a byte range already written
  returns an error; gaps are also rejected.  Once a file is finalised it is
  immutable.
- **Stage-then-finalise**: files are written to a per-session staging area and
  moved to the archive atomically on transfer completion.  A partial upload
  from a crashed session is quarantined and cleaned up automatically.
- **Scoped read-only viewers**: viewer accounts have a configurable `scope`
  (`"all"` or a list of camera/group names).  They can download within their
  scope but cannot write anything.
- **30-day retention** (configurable): the daily cleanup sweep deletes footage
  older than `retention_days` and prunes empty directories.
- **Brute-force lockout**: failed-login attempts are tracked per IP and username
  via libunftp's built-in `FailedLoginsPolicy`.  After `max_attempts` failures
  within `window_secs` the account/IP pair is locked.  `ban_secs` is parsed
  but is **not currently honored** — libunftp's policy has no ban-duration
  parameter; the lockout resets after `window_secs`.  `ban_secs` is reserved
  for a future custom enforcement layer.
- **Opportunistic FTPS**: all connections may upgrade to TLS via `AUTH TLS`;
  individual camera accounts can set `require_tls = true` to make TLS
  mandatory.
- **Encryption at rest** (optional): with `[encryption].recipients` set, every
  clip is age-encrypted *on the fly* to your public key(s) and stored as
  `*.age` — plaintext is never written to disk and only your off-server private
  key can decrypt.  See [Encryption at rest](#encryption-at-rest).
- **Concurrent-session caps**: global and per-account limits on simultaneous
  logged-in sessions (`max_connections`, `max_connections_per_account`),
  enforced in-process; per-IP connection caps via the generated nftables rules
  (`reoftpd nftables`).
- **Live config reload**: `SIGHUP` reloads cameras, viewers, groups, and caps
  without dropping connections (a bad edit is logged and ignored); see
  [Live config reload](#live-config-reload).

## Get the code

There is no public git remote yet, so pick one of these to get the source onto
your machine:

```sh
# A. Clone from your own git host (once the repo has been pushed there).
#    dev.cs.upt.ro is HTTPS-only:
git clone https://dev.cs.upt.ro/<you>/ftp-reolink.git
cd ftp-reolink

# B. Copy it directly from a machine that already has it (no remote needed).
#    Exclude the build dir; it is large and host-specific:
rsync -a --exclude target --exclude .git ./ftp-reolink/ user@vps:~/ftp-reolink/

# C. Air-gapped: ship the whole history as a single file.
#    On the source machine:
git bundle create reoftpd.bundle --all
#    Copy reoftpd.bundle to the target, then:
git clone reoftpd.bundle ftp-reolink && cd ftp-reolink
```

## Build

The crate needs **Rust 1.88+** (it pins toolchain 1.96.0 via `rust-toolchain.toml`,
which `rustup` fetches automatically). A distro's packaged `rustc` on an old
machine is usually too old — use `rustup`. Building needs roughly **1–2 GB RAM**
and ~2 GB disk for `target/`; the final binary is a few MB.

There are two ways to build. On a small/old box, **Strategy B (build elsewhere,
copy the binary)** is the easy path — no toolchain or compile load on the VPS,
and the static binary runs even on ancient userland.

### Strategy A — compile on the machine

**Linux:**

```sh
# Install the Rust toolchain (rustup), not the distro's old rustc:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"

cargo build --release            # toolchain 1.96.0 is auto-installed on first build
# -> target/release/reoftpd
```

On a VPS with **< 1 GB RAM** the final link step (tokio/rustls/argon2) can OOM.
Add temporary swap and reduce parallelism:

```sh
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
cargo build --release -j1        # fewer parallel jobs = lower peak RAM
sudo swapoff /swapfile && sudo rm /swapfile   # afterwards
```

**FreeBSD** (a Tier-2 Rust target):

```sh
pkg install rust                 # ensure `rustc --version` >= 1.88; else use rustup
cargo build --release
# For a more self-contained binary:
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release
```

### Strategy B — build elsewhere, copy the binary (recommended for old/small VPS)

Build a self-contained binary on a capable machine, then copy just that one file.

**Linux (fully-static via musl** — runs on any glibc version, however old**):**

```sh
# On the build host (with rustup):
rustup target add x86_64-unknown-linux-musl       # or aarch64-unknown-linux-musl for ARM
# musl needs its linker for any C deps; this project's crypto is pure Rust, but if a
# build complains, install it:  Debian/Ubuntu: apt-get install musl-tools
cargo build --release --target x86_64-unknown-linux-musl

# Confirm it is fully static, then copy the single binary to the VPS:
ldd target/x86_64-unknown-linux-musl/release/reoftpd   # -> "not a dynamic executable"
scp target/x86_64-unknown-linux-musl/release/reoftpd user@vps:/tmp/reoftpd
# On the VPS:  sudo install -o root -g root -m0755 /tmp/reoftpd /usr/local/bin/reoftpd
```

For **ARM** (`aarch64-unknown-linux-musl`), build natively on an ARM box, or
cross-link from x86 with `apt-get install gcc-aarch64-linux-gnu` plus a cargo
linker setting — native ARM is simpler.

**FreeBSD:** cross-compiling to FreeBSD from Linux needs a sysroot and is fiddly;
build on a FreeBSD host of the **same major version** as the target with
`RUSTFLAGS="-C target-feature=+crt-static" cargo build --release`, then copy
`target/release/reoftpd`.

Verify the copied binary on the target with `reoftpd --help`.

There is also a thin `Makefile` over Cargo (`make build`, `make build-musl
ARCH=x86_64|aarch64`, `make test`, `make lint`, `sudo make install` —
`make help` lists everything). Cargo remains the real build system; the
Makefile just saves typing.

## Continuous integration / prebuilt binaries

CI runs on both hosts: **`.gitlab-ci.yml`** (dev.cs.upt.ro) and
**`.github/workflows/ci.yml`** (GitHub). Both run rustfmt + clippy + tests on
every push, and build a fully-static `x86_64-musl` binary as a downloadable
artifact — so you can grab a prebuilt binary instead of compiling on the VPS at
all. Pushing a git tag (e.g. `v0.1.0`) additionally cuts a Release with that
binary attached (GitLab package registry / GitHub Release).

## Install

### Automated (Linux/FreeBSD)

`scripts/install.sh` does everything in this section in one idempotent, root
run: installs the binary, creates the `reoftpd` system user and directories,
drops in the example config (never overwriting an existing one, mode `0640`),
and installs the systemd units if present. It does NOT generate certs, add
cameras, or start the service — it prints those next steps.

```sh
make build                 # or: make build-musl ARCH=x86_64
sudo ./scripts/install.sh  # set BIN=target/<triple>/release/reoftpd for a musl build
```

Then edit `/etc/reoftpd/reoftpd.toml` and follow the printed next steps
(gencert → add-camera → nftables → enable the service).

### Manual

```sh
# 1. Install the binary
install -o root -g root -m 0755 target/release/reoftpd /usr/local/bin/reoftpd

# 2. Create the system user (Linux)
useradd --system --no-create-home --shell /sbin/nologin reoftpd
# On FreeBSD:
# pw useradd reoftpd -d /nonexistent -s /usr/sbin/nologin -c "reoftpd daemon"

# 3. Create the archive directory
install -d -o reoftpd -g reoftpd -m 0750 /srv/reolink

# 4. Create the config directory and install the config file
install -d -o root -g reoftpd -m 0750 /etc/reoftpd
cp config/reoftpd.example.toml /etc/reoftpd/reoftpd.toml
# Edit /etc/reoftpd/reoftpd.toml before starting the service.
```

## Generate a TLS certificate

A self-signed certificate is sufficient for Reolink cameras on a LAN.

```sh
reoftpd gencert \
  --hostnames nvr.lan 192.168.1.10 \
  --cert /etc/reoftpd/cert.pem \
  --key  /etc/reoftpd/key.pem
chmod 640 /etc/reoftpd/key.pem
chown root:reoftpd /etc/reoftpd/key.pem
```

Set `tls_cert` and `tls_key` in `/etc/reoftpd/reoftpd.toml` to these paths.

## Add camera accounts

Each Reolink camera needs a `[[camera]]` entry.  The easiest way is:

```sh
# Prompts for a password, hashes it, and appends the TOML snippet.
reoftpd add-camera front-door --require-tls
reoftpd add-camera driveway   --require-tls
```

Or hash a password manually and paste the result into the config:

```sh
reoftpd hash-password
```

To override the FTP username (e.g. if the camera firmware rejects hyphens):

```sh
reoftpd add-camera front-door --username frontdoor --require-tls
```

## Add viewer accounts

```sh
# Full access to all cameras
reoftpd add-viewer admin --scope all

# Restricted to the "outdoor" group (as defined in [group])
reoftpd add-viewer patio --scope outdoor

# Restricted to specific cameras
reoftpd add-viewer guard --scope front-door,driveway
```

## Firewall

Open the FTP control port and the passive port range in your firewall:

```sh
# nftables example
nft add rule inet filter input tcp dport 21 accept
nft add rule inet filter input tcp dport 50000-50100 accept
```

**Bind to a LAN or VPN interface — do NOT expose FTP to the public internet.**
FTP is not designed for hostile networks.  The strongest mitigation is binding
`listen` in `[server]` to a private IP (e.g. `192.168.1.10`) and ensuring the
port is not reachable from outside your network.

### In-process connection caps (enforced server-side)

The following limits are checked in-process and are fully enforced at login time:

- `max_connections` — global concurrent-session cap; logins are refused (530)
  once this many sessions are active.  The counter is decremented automatically
  when a session ends.
- `max_connections_per_account` — per-camera concurrent-session cap; logins for
  a single camera account are refused once this many sessions are active for
  that account.
- `idle_timeout_secs` — idle control connections are closed after this many
  seconds.
- `failed_login_lockout` — brute-force lockout tracked per IP and username
  (`ban_secs` is parsed but not yet honored — see the Security guarantees
  section).

### Per-IP rate limits (firewall via nftables)

`max_connections_per_ip` and `new_conns_per_min_per_ip` are enforced at the
firewall layer, not in-process.  reoftpd can generate the nftables rules
automatically from your config:

```sh
reoftpd nftables --config /etc/reoftpd/reoftpd.toml | sudo nft -f -
```

This outputs a ready-to-apply nftables ruleset using `meter` statements to
enforce per-IP connection counts and new-connection rates.  Verify the
generated syntax against your installed `nft` version before applying; nft
syntax for `meter` varies between versions.

`min_transfer_rate_bytes_per_sec` is parsed and stored but is not yet enforced
in-process (reserved for future Slowloris / slow-connection defence).

## Configure your Reolink camera

In the Reolink app or web UI, navigate to **Storage → FTP** and set:

| Field      | Value                                       |
|------------|---------------------------------------------|
| Server     | LAN IP of the reoftpd host (e.g. `192.168.1.10`) |
| Port       | `21`                                        |
| Username   | The `name` field from the `[[camera]]` entry (or `username` if set) |
| Password   | The password you chose when running `add-camera` |
| Directory  | `/` (reoftpd controls the path internally)  |
| Anonymous  | Off                                         |
| Enable TLS | On (if `require_tls = true` is set)         |

Use the camera's **Test** button to verify connectivity.  The test upload
creates a small file; reoftpd quarantines test uploads automatically (they
do not pollute the main archive).

## systemd

```sh
# Install unit files
cp packaging/reoftpd.service         /etc/systemd/system/
cp packaging/reoftpd-cleanup.service /etc/systemd/system/
cp packaging/reoftpd-cleanup.timer   /etc/systemd/system/
systemctl daemon-reload

# Enable and start
systemctl enable --now reoftpd
systemctl enable --now reoftpd-cleanup.timer
```

Check status:

```sh
systemctl status reoftpd
journalctl -u reoftpd -f
```

Apply config changes (account additions, etc.) by restarting the service:

```sh
systemctl restart reoftpd
```

## Live config reload

Editing the config and sending `SIGHUP` reloads cameras, viewers, groups, and
connection caps without dropping any active connections:

```sh
# Using systemd (preferred)
systemctl reload reoftpd

# Or directly (use the PID from systemctl status or pgrep)
kill -HUP <pid>
```

**What reloads without a restart** (live SIGHUP):

- Camera accounts (`[[camera]]`) and viewer accounts (`[[viewer]]`)
- Group definitions (`[group]`)
- Connection caps (`max_connections`, `max_connections_per_account`)

**What still requires a full restart** (cannot hot-reload):

- `listen` address/port, `passive_ports`
- TLS certificate/key paths (`tls_cert`, `tls_key`)
- `idle_timeout_secs`
- `failed_login_lockout` parameters

If the reloaded config contains a parse or validation error, reoftpd logs the
error and continues running with the previous configuration — a bad edit cannot
take down the server.

## Encryption at rest

reoftpd can encrypt every uploaded clip on the fly using
[age](https://age-encryption.org/) (X25519, ChaCha20-Poly1305).  This is
opt-in and configured by adding an `[encryption]` section to the config.

### What it protects

A stolen VPS, stolen disks, or a later root compromise yields only ciphertext.
The attacker cannot read any footage without the private key, which never lives
on the server.

**Honest caveat:** this is *encryption at rest*, not end-to-end encryption.
The plaintext is briefly present in server RAM during an upload (the age stream
cipher runs in the process while the camera sends data).  It is never written to
disk in plaintext form.

### ChaCha20-Poly1305 — no AES-NI required

age uses ChaCha20-Poly1305, which is fast in software on any CPU.  This is a
good fit for old or low-end VPS hardware that lacks AES-NI acceleration.

### Generate a keypair

```sh
reoftpd genkey
```

This prints a public recipient string (`age1...`) and a secret identity string
(`AGE-SECRET-KEY-...`).  **Keep the identity file off the server** — store it
on the machine you use for viewing footage, or in a password manager.  If you
lose the identity, archived footage is unrecoverable.

Configure a second recipient as a backup (e.g. a key stored in cold storage)
so you have a recovery path if the primary identity is lost.

### Configure recipients

Add an `[encryption]` section to `/etc/reoftpd/reoftpd.toml`:

```toml
[encryption]
recipients = [
    "age1primaryRecipientPublicKeyGoesHere",
    "age1backupRecipientPublicKeyGoesHere",
]
```

**Restart required** — unlike account changes, the recipient list cannot be
hot-reloaded via SIGHUP.  Restart the service after any change to `[encryption]`:

```sh
systemctl restart reoftpd
```

### Effect on uploads and viewers

- Every uploaded clip is stored as `<filename>.age` (e.g. `clip.mp4.age`).
- Viewers download the `.age` ciphertext file and decrypt it locally.
- `REST` (byte-range resume) is disabled for encrypted uploads — the entire
  file must be uploaded in a single transfer.

### Viewer decryption

Once you have downloaded a `.age` file, decrypt it with either:

```sh
# Using the reoftpd CLI:
reoftpd decrypt -i identity.txt clip.mp4.age

# Or using the age reference tool directly:
age -d -i identity.txt clip.mp4.age > clip.mp4
```

## Known limitations

- **No in-process privilege drop**: libunftp binds the listening port
  internally; there is no hook to drop root privileges after binding.  The
  daemon therefore runs as the unprivileged `reoftpd` user from the start,
  granted only `CAP_NET_BIND_SERVICE` via the systemd unit
  (`AmbientCapabilities`).  Running as root is not supported and not necessary.

- **Partial live config reload**: `SIGHUP` reloads accounts and connection caps
  without dropping connections, but several settings (bind address/port, passive
  ports, TLS, idle timeout, failed-login lockout) still require a restart.  See
  the "Live config reload" section above.

- **Per-IP connection caps at the firewall only**: `max_connections_per_ip` and
  `new_conns_per_min_per_ip` are not enforced in-process — libunftp 0.23
  provides no peer IP at session end, making in-process per-IP accounting
  unreliable.  Use `reoftpd nftables ... | sudo nft -f -` to apply firewall
  rules.  `min_transfer_rate_bytes_per_sec` is also not yet enforced in-process
  (reserved for future Slowloris defence).

- **Passive port advertisement**: on a NAT'd network, you may need to configure
  the external IP for passive-mode responses.  This is not currently
  configurable; bind to the LAN interface and ensure cameras connect from the
  same network segment to avoid NAT complications.
