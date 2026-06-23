# Encryption at Rest (age, on-the-fly, opt-in) — Design

**Status:** Approved (brainstorming complete)
**Date:** 2026-06-23
**Author:** alin.anton
**Extends:** the reoftpd append-only FTP archive (2026-06-18-reoftpd-design.md)

## 1. Purpose

Encrypt every stored clip with public-key cryptography so that the private key
never resides on the VPS. This closes the currently out-of-scope threat of an
attacker who steals the VPS, images the disks, or gains root **later**: the
on-disk archive is ciphertext only. Decryption happens off-server with a private
key held by the operator/viewers.

This is **encryption at rest**, not end-to-end. Reolink cameras upload plaintext
over FTP (their firmware cannot encrypt), so the clip exists as plaintext in the
server's RAM for the brief upload+encrypt window. An attacker with **live** root
watching uploads could capture it there; the disk never holds plaintext (§4).

## 2. Cryptography

The pure-Rust **`age`** crate (X25519 + ChaCha20-Poly1305, streaming/STREAM
construction, audited format). Chosen over libsodium (C) to keep the
fully-static musl binary and the pure-Rust crypto stack (rustls, argon2) intact.
ChaCha20-Poly1305 is fast in software — good on an old VPS without AES-NI. Output
is interoperable with the standard `age`/`rage` CLIs.

Each clip is encrypted to **all** configured recipients (age supports multiple
recipients); any one corresponding identity (private key) can decrypt. This
enables an offline backup key held separately from the day-to-day key.

## 3. Configuration

New optional section:
```toml
[encryption]
recipients = ["age1qz...", "age1bak..."]   # one or more age X25519 public keys
```
- **Absent or empty list → encryption OFF**, behaviour identical to today
  (backward compatible).
- The server holds **only public recipient strings** — safe to store on the VPS
  and safe to commit. Changing `recipients` takes effect on **restart** (§8),
  not on SIGHUP.
- Validation (`config::validate`): if the section is present, `recipients` must
  be non-empty and every entry must parse as a valid age recipient (`age1...`).

## 4. On-the-fly encryption (the core)

`ReoBackend` is given the parsed recipients at construction (from config). In
`StorageBackend::put`, when recipients are configured:

1. The incoming byte stream is fed through an `age` streaming **encryptor**
   keyed to the recipients; the **ciphertext** is what gets written to the
   staging file. Plaintext is therefore **never written to disk** — it exists
   only in per-chunk RAM buffers.
2. The stored file name gains an **`.age`** suffix (`clip.mp4` →
   `clip.mp4.age`). The virtual path the camera sent is unchanged; only the
   real stored filename gets the suffix.
3. **`REST`/resume is rejected** when encryption is on (`REST > 0` → `550`): the
   server has no private key and cannot resume an encrypted stream by plaintext
   offset. Reolink uses whole-file `STOR` (offset 0), so nothing is lost in
   practice. An interrupted upload simply re-uploads from scratch.
4. **All existing append-only guarantees still hold, on the ciphertext:**
   no-overwrite (an existing finalized `*.age` name is refused at any offset),
   stage-then-finalize (ciphertext staging `<final>.age.reoftpd-partial` →
   atomic no-clobber `hard_link` → immutable `<final>.age`), the capability
   gate, and `ScopeMap` path containment.
5. The Reolink **test-file quarantine stays UNENCRYPTED** — those are throwaway
   probe files that must be overwritable and are cleaned aggressively; they
   carry no footage.

**Async/sync bridge:** the `age` crate exposes a synchronous `Write`-based
encryptor. `put` receives an `AsyncRead`. The implementation bridges them by
running the chunked encrypt-copy under `tokio::task::spawn_blocking` (or
`block_in_place`), reading from the async body into a synchronous age
`StreamWriter` that writes to the staging file. Memory stays bounded (chunked).

When encryption is OFF, `put` behaves exactly as today (plaintext staging,
non-overlap rule, REST resume supported, no `.age` suffix).

## 5. CLI

- `reoftpd genkey [--output identity.txt]` — generate an age keypair. Prints the
  **public** recipient (`age1...`) to stdout (for the config) and writes the
  **private** identity to `--output` (or stdout if omitted). Prints a loud
  warning: keep the identity OFF the server; losing it makes the archive
  permanently unrecoverable; configure a second backup recipient.
- `reoftpd decrypt --identity identity.txt [--output DIR] <file.age>...` —
  local decryption convenience so viewers need no separate tool. Reads the age
  identity, decrypts each input to its name minus `.age` (in `--output` dir, or
  alongside the input). Equivalent to `age -d -i identity.txt file.age`.

## 6. Viewer flow

Unchanged authentication and scoping — viewers still authenticate and are scoped
to which cameras' files they may download (defense in depth; the server cannot
read the content either way). They `RETR` the `*.age` ciphertext, then decrypt
locally with `reoftpd decrypt -i identity.txt clip.mp4.age` (or the `age` CLI).

## 7. Retention & interactions

- Retention deletes old `*.age` files by mtime exactly as before (it never reads
  them); orphaned `*.reoftpd-partial` cleanup is unchanged.
- Connection caps, SIGHUP reload, privilege model, nftables — all unchanged.
- Encryption is purely additive: a transform in the `put` write path + a
  filename suffix + new CLI subcommands + a config section.

## 8. SIGHUP reload

`recipients` is part of the config and should reload on SIGHUP like accounts and
caps. Because `ReoBackend` is constructed per the recipients, the cleanest
approach mirrors the accounts pattern: hold the recipients behind the same
`ArcSwap`-style reloadable state the backend reads per `put`, OR (simpler, and
acceptable) document that changing `[encryption].recipients` requires a restart.
**Decision:** treat recipient changes as **restart-required** for v1 (consistent
with TLS/passive-ports, which already need a restart), to avoid threading
mutable crypto state through the per-connection backend. Document it.

## 9. Components / files

- `Cargo.toml` — add `age = "0.11"` (confirm latest at implementation).
- `src/crypto.rs` (new) — parse recipient strings → `age::x25519::Recipient`s;
  an `encrypt_stream(recipients, reader, writer)` helper (the sync STREAM
  encrypt-copy); a `decrypt` helper for the CLI; identity generation for
  `genkey`. Unit-tested in isolation.
- `src/config.rs` — `[encryption]` section + validation.
- `src/backend.rs` — wire `crypto::encrypt_stream` into `put` (on-the-fly),
  apply `.age` suffix, reject `REST > 0` when encrypting; `ReoBackend` gains a
  `recipients` field.
- `src/server.rs` — parse recipients from config and pass them into the
  `ReoBackend` generator closure.
- `src/cli.rs` / `src/main.rs` — `genkey` and `decrypt` subcommands.
- `config/reoftpd.example.toml`, `README.md` — `[encryption]` example + a
  "Encryption at rest" section (key handling, backup key, at-rest-not-E2E
  caveat, decryption instructions, restart-required note).
- `tests/integration.rs` — end-to-end encrypted upload + download + decrypt.

## 10. Testing

Unit (`src/crypto.rs`):
- encrypt→decrypt round-trip recovers the exact plaintext.
- multiple recipients: each of N identities independently decrypts.
- recipient-string parsing: valid `age1...` accepted; garbage rejected.
- the encrypted output is NOT equal to the plaintext input.

Backend:
- with recipients configured, `put` of a known plaintext produces a stored file
  whose bytes differ from the plaintext AND that decrypts (with the test
  identity) back to the exact plaintext; the stored name ends in `.age`.
- `REST > 0` is rejected when encryption is on.
- with encryption OFF, behaviour and stored bytes are unchanged from today.

CLI: `genkey` emits a parseable recipient + a working identity; `decrypt`
round-trips a file produced by the backend; output matches the `age` CLI format.

Integration (`tests/integration.rs`, encryption-on variant): uploader `STOR`s a
clip → the on-disk archive file is ciphertext (≠ plaintext, ends `.age`) →
viewer `RETR`s the `.age` → `reoftpd decrypt` with the identity recovers the
exact original bytes.

## 11. Out of scope
End-to-end (camera-side) encryption; encrypting the test-file quarantine;
hot-reload of `[encryption].recipients` (restart-required in v1); key rotation /
re-encrypting an existing archive.
