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
    let pasv_hi = pasv_lo + 20;

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
        let _ = rt.block_on(reoftpd::server::run(cfg));
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
        let expected_path = root.join("front-door").join("clip.mp4");
        assert!(
            expected_path.exists(),
            "assertion 1 failed: clip.mp4 must exist at {}", expected_path.display()
        );
        let contents = std::fs::read(&expected_path).expect("read clip.mp4");
        assert_eq!(
            contents, b"hello",
            "assertion 1 failed: clip.mp4 contents must be 'hello'"
        );

        // Assertion 2: STOR same name again -> Err (no overwrite)
        let result = ftp.put_file("clip.mp4", &mut Cursor::new(b"overwrite" as &[u8]));
        assert!(
            result.is_err(),
            "assertion 2 failed: second STOR of clip.mp4 must fail (no overwrite), got Ok"
        );

        // Assertion 3: RETR -> Err (uploader cannot read)
        let result = ftp.retr_as_buffer("clip.mp4");
        assert!(
            result.is_err(),
            "assertion 3 failed: RETR by uploader must fail, got Ok"
        );

        // Assertion 4: DELE -> Err (uploader cannot delete)
        let result = ftp.rm("clip.mp4");
        assert!(
            result.is_err(),
            "assertion 4 failed: DELE by uploader must fail, got Ok"
        );

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
            "assertion 5b failed: sub/c2.mp4 must exist at {}", expected_sub.display()
        );

        // Assertion 6: RMD sub -> Err (uploader cannot rmdir)
        let result = ftp.rmdir("sub");
        assert!(
            result.is_err(),
            "assertion 6 failed: RMD by uploader must fail, got Ok"
        );

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
            "assertion 7c failed: test.txt must be in .quarantine/, path: {}", quarantine_path.display()
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

        // Assertion 9: STOR -> Err (viewer cannot write)
        let result = ftp.put_file("/front-door/evil.mp4", &mut Cursor::new(b"evil" as &[u8]));
        assert!(
            result.is_err(),
            "assertion 9 failed: STOR by viewer must fail, got Ok"
        );

        // Assertion 10: DELE -> Err (viewer cannot delete)
        let result = ftp.rm("/front-door/clip.mp4");
        assert!(
            result.is_err(),
            "assertion 10 failed: DELE by viewer must fail, got Ok"
        );

        ftp.quit().ok();
    }

    // Keep dir alive until end so the archive is not deleted under the server.
    drop(dir);
}
