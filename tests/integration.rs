//! End-to-end integration test for reoftpd.
//!
//! Pattern: async libunftp server on a background thread with its own tokio runtime;
//! driven by suppaftp sync FtpStream from a plain #[test].
//!
//! Assertions:
//! UPLOADER (front-door / pw):
//!   1. STOR new file -> Ok; file exists on disk with correct bytes.
//!   2. STOR same name again -> Err (no overwrite / append-only finalized).
//!   3. RETR file -> Err (uploaders cannot read).
//!   4. DELE file -> Err (uploaders cannot delete).
//!   5. MKD sub -> Ok; STOR sub/c2.mp4 -> Ok; file exists on disk.
//!   6. RMD sub -> Err (uploaders cannot rmdir).
//!   7. Reolink test file: STOR test.txt twice -> both Ok; file under .quarantine/; NOT at root.
//!
//! VIEWER (admin / vp, scope all):
//!   8. LIST "/" shows front-door; RETR /front-door/clip.mp4 -> Ok, contents "hello".
//!   9. STOR /front-door/evil.mp4 -> Err (viewers cannot write).
//!  10. DELE /front-door/clip.mp4 -> Err (viewers cannot delete).

use std::io::Cursor;
use std::net::TcpStream;
use std::time::{Duration, Instant};
use suppaftp::FtpStream;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Grab an ephemeral port by binding then immediately dropping.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

/// Block until the control port accepts a TCP connection (or panic after 8s).
fn wait_for_port(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for port {port}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Connect an FtpStream in passive mode; retry up to 5 times with 200ms gaps.
fn connect_ftp(port: u16) -> FtpStream {
    for attempt in 0..5 {
        match FtpStream::connect(format!("127.0.0.1:{port}")) {
            Ok(s) => return s,
            Err(e) => {
                if attempt == 4 {
                    panic!("failed to connect to FTP port {port} after 5 attempts: {e}");
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
    unreachable!()
}

/// Assert that `result` is a server-side permanent rejection (5xx FTP reply).
///
/// The suppaftp API wraps any non-expected server reply in
/// `FtpError::UnexpectedResponse(Response)` where `Response.status.code()`
/// carries the numeric FTP reply code.  A 5xx code means the server issued
/// a Permanent Negative Completion Reply — this is what we need to verify
/// for security-enforcement assertions.
fn assert_server_rejected<T: std::fmt::Debug>(result: Result<T, suppaftp::FtpError>, what: &str) {
    match result {
        Err(suppaftp::FtpError::UnexpectedResponse(resp)) => {
            let code = resp.status.code();
            assert!(
                (500..600).contains(&code),
                "{what}: expected a 5xx server rejection, got reply {:?} (code {})",
                resp,
                code
            );
        }
        other => panic!(
            "{what}: expected a server 5xx rejection (UnexpectedResponse), got {:?}",
            other
        ),
    }
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_append_only_and_scoped_read() {
    // ---- 1. Build a real tempdir and config with real argon2id password hashes ----
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    let cam_hash = reoftpd::hashing::hash_password("pw").expect("cam hash");
    let viewer_hash = reoftpd::hashing::hash_password("vp").expect("viewer hash");

    let ctrl = free_port();
    // Use a wider passive range to reduce port-reuse flakiness.
    let pasv_lo = free_port();
    let pasv_hi = pasv_lo + 30;

    let toml = format!(
        r#"
[server]
listen = "127.0.0.1"
port = {ctrl}
passive_ports = [{pasv_lo}, {pasv_hi}]

[archive]
root = "{root}"
retention_days = 30

[limits]
max_connections = 64
max_connections_per_ip = 8
new_conns_per_min_per_ip = 60
idle_timeout_secs = 30
min_transfer_rate_bytes_per_sec = 1
failed_login_lockout = {{ max_attempts = 50, window_secs = 60, ban_secs = 60 }}

[[camera]]
name = "front-door"
upload_password_hash = "{cam_hash}"

[[viewer]]
name = "admin"
password_hash = "{viewer_hash}"
scope = "all"
"#,
        root = root.display()
    );

    let cfg = reoftpd::config::parse_str(&toml).expect("parse config");
    cfg.validate().expect("validate config");

    // ---- 2. Start the server on a background thread ----
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        // Pass a dummy path — this integration test builds config from a string
        // so there is no file on disk for SIGHUP reload to read.
        let dummy_path = std::path::PathBuf::from("/dev/null");
        let _ = rt.block_on(reoftpd::server::run(cfg, dummy_path));
    });

    wait_for_port(ctrl);

    // ---- 3. UPLOADER session ----
    {
        let mut ftp = connect_ftp(ctrl);
        ftp.login("front-door", "pw").expect("uploader login");

        // Assertion 1: STOR new file -> Ok
        let result = ftp.put_file("clip.mp4", &mut Cursor::new(b"hello" as &[u8]));
        assert!(
            result.is_ok(),
            "assertion 1 failed: first STOR of clip.mp4 must succeed, got: {:?}",
            result.err()
        );
        // Verify the file landed at the right path with correct contents.
        let expected_clip_path = root.join("front-door").join("clip.mp4");
        assert!(
            expected_clip_path.exists(),
            "assertion 1 failed: clip.mp4 must exist at {}",
            expected_clip_path.display()
        );
        let contents = std::fs::read(&expected_clip_path).expect("read clip.mp4");
        assert_eq!(
            contents, b"hello",
            "assertion 1 failed: clip.mp4 contents must be 'hello'"
        );

        // Assertion 2: STOR same name again -> server 5xx (no overwrite)
        let result = ftp.put_file("clip.mp4", &mut Cursor::new(b"overwrite" as &[u8]));
        assert_server_rejected(
            result,
            "assertion 2: second STOR of clip.mp4 (no overwrite)",
        );
        // Verify file was NOT modified by the rejected STOR.
        let after = std::fs::read(&expected_clip_path).expect("re-read clip.mp4");
        assert_eq!(
            after, b"hello",
            "clip.mp4 was overwritten despite the STOR being rejected"
        );

        // Assertion 3: RETR -> server 5xx (uploader cannot read)
        let result = ftp.retr_as_buffer("clip.mp4");
        assert_server_rejected(result, "assertion 3: RETR by uploader (read denied)");

        // Assertion 4: DELE -> server 5xx (uploader cannot delete)
        let result = ftp.rm("clip.mp4");
        assert_server_rejected(result, "assertion 4: DELE by uploader (delete denied)");

        // Assertion 5: MKD sub -> Ok; STOR sub/c2.mp4 -> Ok
        let mkdir_result = ftp.mkdir("sub");
        assert!(
            mkdir_result.is_ok(),
            "assertion 5a failed: MKD sub must succeed, got: {:?}",
            mkdir_result.err()
        );
        let result = ftp.put_file("sub/c2.mp4", &mut Cursor::new(b"data2" as &[u8]));
        assert!(
            result.is_ok(),
            "assertion 5b failed: STOR sub/c2.mp4 must succeed, got: {:?}",
            result.err()
        );
        let expected_sub = root.join("front-door").join("sub").join("c2.mp4");
        assert!(
            expected_sub.exists(),
            "assertion 5b failed: sub/c2.mp4 must exist at {}",
            expected_sub.display()
        );

        // Assertion 6: RMD sub -> server 5xx (uploader cannot rmdir)
        let result = ftp.rmdir("sub");
        assert_server_rejected(result, "assertion 6: RMD by uploader (rmdir denied)");

        // Assertion 7: Reolink test file STOR twice -> both Ok; lands in .quarantine/
        let result1 = ftp.put_file("test.txt", &mut Cursor::new(b"probe1" as &[u8]));
        assert!(
            result1.is_ok(),
            "assertion 7a failed: first STOR of test.txt must succeed, got: {:?}",
            result1.err()
        );
        let result2 = ftp.put_file("test.txt", &mut Cursor::new(b"probe2" as &[u8]));
        assert!(
            result2.is_ok(),
            "assertion 7b failed: second STOR of test.txt must succeed (quarantine allows overwrite), got: {:?}",
            result2.err()
        );
        let quarantine_path = root.join("front-door").join(".quarantine").join("test.txt");
        assert!(
            quarantine_path.exists(),
            "assertion 7c failed: test.txt must be in .quarantine/, path: {}",
            quarantine_path.display()
        );
        let root_path = root.join("front-door").join("test.txt");
        assert!(
            !root_path.exists(),
            "assertion 7d failed: test.txt must NOT exist at archive root ({}), only in .quarantine/",
            root_path.display()
        );

        ftp.quit().ok();
    }

    // ---- 4. VIEWER session ----
    {
        let mut ftp = connect_ftp(ctrl);
        ftp.login("admin", "vp").expect("viewer login");

        // Assertion 8a: LIST "/" shows front-door
        let listing = ftp.nlst(Some("/")).expect("viewer LIST / must succeed");
        let has_front_door = listing.iter().any(|e| e.contains("front-door"));
        assert!(
            has_front_door,
            "assertion 8a failed: LIST / must show front-door, got: {:?}",
            listing
        );

        // Assertion 8b: RETR /front-door/clip.mp4 -> Ok, contents "hello"
        let buf = ftp
            .retr_as_buffer("/front-door/clip.mp4")
            .expect("assertion 8b failed: viewer RETR /front-door/clip.mp4 must succeed");
        assert_eq!(
            buf.into_inner(),
            b"hello",
            "assertion 8b failed: viewer RETR contents must be 'hello'"
        );

        // Assertion 9: STOR -> server 5xx (viewer cannot write)
        let result = ftp.put_file("/front-door/evil.mp4", &mut Cursor::new(b"evil" as &[u8]));
        assert_server_rejected(result, "assertion 9: STOR by viewer (write denied)");

        // Assertion 10: DELE -> server 5xx (viewer cannot delete)
        let result = ftp.rm("/front-door/clip.mp4");
        assert_server_rejected(result, "assertion 10: DELE by viewer (delete denied)");

        ftp.quit().ok();
    }

    // Keep dir alive until end so the archive is not deleted under the server.
    drop(dir);
}

// ---------------------------------------------------------------------------
// Session-cap test
// ---------------------------------------------------------------------------

/// With `max_connections = 1`, a second login is refused while the first holds
/// the slot; after the first session closes a new login succeeds.
#[test]
fn global_session_cap_refuses_second_login() {
    // ---- Build config ----
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    let cam_hash = reoftpd::hashing::hash_password("pw").expect("cam hash");

    let ctrl = free_port();
    let pasv_lo = free_port();
    let pasv_hi = pasv_lo + 30;

    let toml = format!(
        r#"
[server]
listen = "127.0.0.1"
port = {ctrl}
passive_ports = [{pasv_lo}, {pasv_hi}]

[archive]
root = "{root}"
retention_days = 30

[limits]
max_connections = 1
max_connections_per_ip = 8
new_conns_per_min_per_ip = 60
idle_timeout_secs = 30
min_transfer_rate_bytes_per_sec = 1
# Keep lockout threshold very high so the refused login doesn't trip it.
failed_login_lockout = {{ max_attempts = 50, window_secs = 60, ban_secs = 60 }}

[[camera]]
name = "front-door"
upload_password_hash = "{cam_hash}"
"#,
        root = root.display()
    );

    let cfg = reoftpd::config::parse_str(&toml).expect("parse config");
    cfg.validate().expect("validate config");

    // ---- Start the server on a background thread ----
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let dummy_path = std::path::PathBuf::from("/dev/null");
        let _ = rt.block_on(reoftpd::server::run(cfg, dummy_path));
    });

    wait_for_port(ctrl);

    // ---- First session logs in and stays open ----
    let mut ftp1 = connect_ftp(ctrl);
    ftp1.login("front-door", "pw")
        .expect("first login must succeed");
    // PWD ensures the session is fully established and LoggedIn has been dispatched.
    let _ = ftp1.pwd().unwrap();

    // Give the presence event a moment to register (LoggedIn fires just after auth).
    std::thread::sleep(std::time::Duration::from_millis(200));

    // ---- Second login must be refused while the first holds the only slot ----
    let mut ftp2 = suppaftp::FtpStream::connect(("127.0.0.1", ctrl)).unwrap();
    let second = ftp2.login("front-door", "pw");
    assert!(
        second.is_err(),
        "second login should be refused at global cap = 1, got: {:?}",
        second.ok()
    );

    // ---- Close the first; a new login then succeeds ----
    ftp1.quit().ok();
    // Give the LoggedOut event time to decrement the counter.
    std::thread::sleep(std::time::Duration::from_millis(200));

    let mut ftp3 = connect_ftp(ctrl);
    assert!(
        ftp3.login("front-door", "pw").is_ok(),
        "login should succeed after the first session closed"
    );
    ftp3.quit().ok();

    // Keep dir alive until end.
    drop(dir);
}

// ---------------------------------------------------------------------------
// Encrypted upload test
// ---------------------------------------------------------------------------

/// Upload a known plaintext while encryption is configured; verify:
///   1. The on-disk file is `<root>/front-door/clip.mp4.age` and its bytes are NOT the plaintext.
///   2. No plaintext `<root>/front-door/clip.mp4` file exists.
///   3. A viewer can RETR the `.age` ciphertext file.
///   4. `reoftpd::crypto::decrypt_stream` with the test identity recovers the exact original bytes.
#[test]
fn encrypted_upload_is_ciphertext_on_disk_and_decryptable() {
    // ---- 1. Generate an age keypair for this test ----
    let (pubkey, secret) = reoftpd::crypto::generate_identity();

    // ---- 2. Build config with [encryption] ----
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    let cam_hash = reoftpd::hashing::hash_password("pw").expect("cam hash");
    let viewer_hash = reoftpd::hashing::hash_password("vp").expect("viewer hash");

    let ctrl = free_port();
    let pasv_lo = free_port();
    let pasv_hi = pasv_lo + 30;

    let toml = format!(
        r#"
[server]
listen = "127.0.0.1"
port = {ctrl}
passive_ports = [{pasv_lo}, {pasv_hi}]

[archive]
root = "{root}"
retention_days = 30

[limits]
max_connections = 64
max_connections_per_ip = 8
new_conns_per_min_per_ip = 60
idle_timeout_secs = 30
min_transfer_rate_bytes_per_sec = 1
failed_login_lockout = {{ max_attempts = 200, window_secs = 60, ban_secs = 60 }}

[encryption]
recipients = ["{pubkey}"]

[[camera]]
name = "front-door"
upload_password_hash = "{cam_hash}"

[[viewer]]
name = "admin"
password_hash = "{viewer_hash}"
scope = "all"
"#,
        root = root.display()
    );

    let cfg = reoftpd::config::parse_str(&toml).expect("parse config");
    cfg.validate().expect("validate config");

    // ---- 3. Start the server on a background thread ----
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let dummy_path = std::path::PathBuf::from("/dev/null");
        let _ = rt.block_on(reoftpd::server::run(cfg, dummy_path));
    });

    wait_for_port(ctrl);

    // ---- 4. Upload a known plaintext as the camera ----
    let body = b"END TO END ARCHIVE BYTES";
    {
        let mut up = connect_ftp(ctrl);
        up.login("front-door", "pw").expect("uploader login");
        up.put_file("clip.mp4", &mut &body[..])
            .expect("upload must succeed");
        up.quit().ok();
    }

    // ---- 5. On-disk assertions: .age file exists; plaintext file does not ----
    let archive_root = root;
    let stored_path = archive_root.join("front-door/clip.mp4.age");
    let stored = std::fs::read(&stored_path).expect("encrypted file must exist on disk");
    assert_ne!(
        stored.as_slice(),
        &body[..],
        "archive file must be ciphertext, not plaintext"
    );
    assert!(
        !archive_root.join("front-door/clip.mp4").exists(),
        "plaintext file must NOT exist on disk"
    );

    // ---- 6. Viewer downloads the .age ciphertext ----
    let downloaded = {
        let mut vw = connect_ftp(ctrl);
        vw.login("admin", "vp").expect("viewer login");
        let buf = vw
            .retr_as_buffer("/front-door/clip.mp4.age")
            .expect("viewer must be able to RETR the .age file");
        vw.quit().ok();
        buf.into_inner()
    };
    assert_ne!(
        downloaded.as_slice(),
        &body[..],
        "downloaded bytes must be ciphertext"
    );

    // ---- 7. Decrypt with the test identity; expect exact original ----
    let id = <age::x25519::Identity as std::str::FromStr>::from_str(&secret).unwrap();
    let mut out = Vec::new();
    reoftpd::crypto::decrypt_stream(&id, &downloaded[..], &mut out)
        .expect("decrypt must succeed with the test identity");
    assert_eq!(
        out, body,
        "decrypted bytes must equal the original plaintext"
    );

    // Keep dir alive until end.
    drop(dir);
}
