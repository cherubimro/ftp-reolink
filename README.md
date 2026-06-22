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

## Build

```sh
cargo build --release
```

The resulting binary is at `target/release/reoftpd`.

**FreeBSD note**: FreeBSD is a Tier-2 Rust target.  The binary links against
the system libc by default.  For a more portable build, cross-compile with a
musl-libc target or set `RUSTFLAGS="-C target-feature=+crt-static"` with an
appropriate target triple.

## Install

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

Connection-flood rate limits (`max_connections`, `max_connections_per_ip`,
`new_conns_per_min_per_ip`) and `min_transfer_rate_bytes_per_sec` are parsed
and stored but are not yet wired into the server.  Enforce flood limits at the
firewall layer (nftables `limit rate` / `meter` rules).  In-server brute-force
lockout (`failed_login_lockout`) and idle connection timeout
(`idle_timeout_secs`) are active.  Note that `failed_login_lockout.ban_secs`
is parsed but not yet honored — see the Security guarantees section.

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

## Known limitations

- **No in-process privilege drop**: libunftp binds the listening port
  internally; there is no hook to drop root privileges after binding.  The
  daemon therefore runs as the unprivileged `reoftpd` user from the start,
  granted only `CAP_NET_BIND_SERVICE` via the systemd unit
  (`AmbientCapabilities`).  Running as root is not supported and not necessary.

- **No live config reload (SIGHUP)**: account changes and other configuration
  edits take effect only after `systemctl restart reoftpd`.  A `SIGHUP` reload
  path is not yet implemented.

- **Per-IP / global connection caps not yet enforced server-side**: the
  `max_connections`, `max_connections_per_ip`, `new_conns_per_min_per_ip`, and
  `min_transfer_rate_bytes_per_sec` fields are parsed and validated but are not
  yet wired into the server.  Use firewall rules to enforce connection-rate
  limits; slow-connection (Slowloris) defence is not yet implemented in-process.
  The in-server controls that _are_ active are `idle_timeout_secs` and
  `failed_login_lockout` (see note above regarding `ban_secs`).

- **Passive port advertisement**: on a NAT'd network, you may need to configure
  the external IP for passive-mode responses.  This is not currently
  configurable; bind to the LAN interface and ensure cameras connect from the
  same network segment to avoid NAT complications.
