#!/bin/sh
# reoftpd — first-time system provisioning. Run as root (sudo).
#
# Idempotent: safe to re-run. It NEVER overwrites an existing config file.
# It installs the binary, creates the system user and directories, drops in the
# example config (once), and installs the systemd units if systemd is present.
# It does NOT generate certs, add cameras, or start the service — do those after
# editing the config (see the printed next steps).
#
# Override defaults via env, e.g.:
#   sudo BIN=target/x86_64-unknown-linux-musl/release/reoftpd ./scripts/install.sh
set -eu

PREFIX="${PREFIX:-/usr/local}"
BIN="${BIN:-./target/release/reoftpd}"
ARCHIVE="${ARCHIVE:-/srv/reolink}"
CONFDIR="${CONFDIR:-/etc/reoftpd}"
USER_NAME="${USER_NAME:-reoftpd}"

if [ "$(id -u)" -ne 0 ]; then
	echo "error: run as root (use sudo)" >&2
	exit 1
fi

if [ ! -x "$BIN" ]; then
	echo "error: binary not found at '$BIN'. Build it first:" >&2
	echo "       make build           (or)  make build-musl ARCH=x86_64" >&2
	echo "       then set BIN=... if you used a musl/cross target." >&2
	exit 1
fi

# 1. Binary
install -o root -g root -m0755 "$BIN" "$PREFIX/bin/reoftpd"
echo "installed binary -> $PREFIX/bin/reoftpd"

# 2. System user (Linux useradd / FreeBSD pw), only if missing
if id "$USER_NAME" >/dev/null 2>&1; then
	echo "user '$USER_NAME' already exists; left unchanged"
elif command -v useradd >/dev/null 2>&1; then
	useradd --system --no-create-home --shell /sbin/nologin "$USER_NAME"
	echo "created system user '$USER_NAME'"
elif command -v pw >/dev/null 2>&1; then
	pw useradd "$USER_NAME" -d /nonexistent -s /usr/sbin/nologin -c "reoftpd daemon"
	echo "created system user '$USER_NAME'"
else
	echo "error: no useradd/pw found; create the '$USER_NAME' user manually" >&2
	exit 1
fi

# 3. Archive directory (owned by the daemon user)
install -d -o "$USER_NAME" -g "$USER_NAME" -m0750 "$ARCHIVE"
echo "archive directory -> $ARCHIVE"

# 4. Config directory + example config (NEVER clobber an existing config).
#    Mode 0640 root:reoftpd — the config holds password hashes; not world-readable.
install -d -o root -g "$USER_NAME" -m0750 "$CONFDIR"
if [ -f "$CONFDIR/reoftpd.toml" ]; then
	echo "$CONFDIR/reoftpd.toml exists; left unchanged"
else
	install -o root -g "$USER_NAME" -m0640 config/reoftpd.example.toml "$CONFDIR/reoftpd.toml"
	echo "installed example config -> $CONFDIR/reoftpd.toml  (EDIT IT before starting)"
fi

# 5. systemd units, if systemd is the init
if [ -d /run/systemd/system ]; then
	for u in reoftpd.service reoftpd-cleanup.service reoftpd-cleanup.timer; do
		install -m0644 "packaging/$u" "/etc/systemd/system/$u"
	done
	systemctl daemon-reload
	echo "installed systemd units (run: systemctl enable --now reoftpd reoftpd-cleanup.timer)"
else
	echo "no systemd detected; run 'reoftpd serve --config $CONFDIR/reoftpd.toml' under your init,"
	echo "and schedule 'reoftpd cleanup' from cron for retention."
fi

cat <<EOF

Next steps:
  1. Edit $CONFDIR/reoftpd.toml
  2. reoftpd gencert --hostnames <host> --cert $CONFDIR/cert.pem --key $CONFDIR/key.pem
  3. reoftpd add-camera <name> --require-tls        # appends a hashed entry to the config
  4. reoftpd nftables --config $CONFDIR/reoftpd.toml | nft -f -   # per-IP firewall caps
  5. systemctl enable --now reoftpd reoftpd-cleanup.timer   # (or your init's equivalent)
EOF
