#![forbid(unsafe_code)]

use std::io::{self, BufRead, Write};
use std::time::{Duration, SystemTime};

use clap::Parser;
use reoftpd::cli::{Cli, Command};

/// Read a password: from `REOFTPD_PASSWORD` env var if set (non-interactive /
/// test use), otherwise read one line from stdin.
///
/// Note: we do NOT suppress terminal echo — a simple line read is used for
/// clarity and testability. Production deployments should supply the env var
/// from a secrets manager rather than typing interactively.
fn read_password(prompt: &str) -> anyhow::Result<String> {
    if let Ok(pw) = std::env::var("REOFTPD_PASSWORD") {
        return Ok(pw);
    }
    eprint!("{prompt}");
    io::stderr().flush().ok();
    let stdin = io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    // Trim trailing newline.
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialise structured logging so tracing events appear on stderr.
    tracing_subscriber::fmt().init();

    let cli = Cli::parse();

    match cli.command {
        // ------------------------------------------------------------------
        // serve: load config, start FTP server.
        // ------------------------------------------------------------------
        Command::Serve { config } => {
            let cfg = reoftpd::config::load(&config)?;
            reoftpd::server::run(cfg, config).await?;
        }

        // ------------------------------------------------------------------
        // cleanup: run retention sweep (synchronous; called inside async fn).
        // ------------------------------------------------------------------
        Command::Cleanup { config, dry_run } => {
            let cfg = reoftpd::config::load(&config)?;
            let retention = Duration::from_secs(cfg.archive.retention_days * 86_400);
            // TTLs for quarantine and staging directories. Not carried in the
            // config schema (that is per the current config design); we use
            // sensible fixed constants: 1 hour each.
            const QUARANTINE_TTL: Duration = Duration::from_secs(3_600);
            const STAGING_TTL: Duration = Duration::from_secs(3_600);
            let now = SystemTime::now();
            let report = reoftpd::retention::sweep(
                &cfg.archive.root,
                retention,
                QUARANTINE_TTL,
                STAGING_TTL,
                now,
                dry_run,
            )?;
            println!("deleted {} file(s):", report.deleted.len());
            for p in &report.deleted {
                println!("  {}", p.display());
            }
            println!("pruned {} empty director(ies):", report.pruned_dirs.len());
            for p in &report.pruned_dirs {
                println!("  {}", p.display());
            }
        }

        // ------------------------------------------------------------------
        // add-camera: prompt for password, hash it, append TOML snippet.
        // ------------------------------------------------------------------
        Command::AddCamera {
            name,
            username,
            require_tls,
        } => {
            let config = std::env::var("REOFTPD_CONFIG")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from("/etc/reoftpd/reoftpd.toml"));
            let password = read_password(&format!("Password for camera {name}: "))?;
            let hash =
                reoftpd::hashing::hash_password(&password).map_err(|e| anyhow::anyhow!("{e}"))?;
            let snippet =
                reoftpd::cli::render_camera_entry(&name, username.as_deref(), &hash, require_tls);
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&config)
                .map_err(|e| anyhow::anyhow!("opening {}: {e}", config.display()))?;
            f.write_all(snippet.as_bytes())?;
            println!("Camera {name:?} added to {}.", config.display());
        }

        // ------------------------------------------------------------------
        // add-viewer: prompt for password, hash it, append TOML snippet.
        // ------------------------------------------------------------------
        Command::AddViewer { name, scope } => {
            let config = std::env::var("REOFTPD_CONFIG")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from("/etc/reoftpd/reoftpd.toml"));
            let password = read_password(&format!("Password for viewer {name}: "))?;
            let hash =
                reoftpd::hashing::hash_password(&password).map_err(|e| anyhow::anyhow!("{e}"))?;
            let snippet = reoftpd::cli::render_viewer_entry(&name, &hash, &scope);
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&config)
                .map_err(|e| anyhow::anyhow!("opening {}: {e}", config.display()))?;
            f.write_all(snippet.as_bytes())?;
            println!("Viewer {name:?} added to {}.", config.display());
        }

        // ------------------------------------------------------------------
        // hash-password: read password, print PHC string.
        // ------------------------------------------------------------------
        Command::HashPassword => {
            let password = read_password("Password: ")?;
            let hash =
                reoftpd::hashing::hash_password(&password).map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("{hash}");
        }

        // ------------------------------------------------------------------
        // nftables: print nftables ruleset enforcing connection caps.
        // ------------------------------------------------------------------
        Command::Nftables { config } => {
            let cfg = reoftpd::config::load(&config)?;
            print!("{}", reoftpd::nftables::render_nftables(&cfg));
        }

        // ------------------------------------------------------------------
        // gencert: generate self-signed cert + key, write files.
        // ------------------------------------------------------------------
        Command::Gencert {
            hostnames,
            cert,
            key,
        } => {
            let (cert_pem, key_pem) = reoftpd::tls::generate_self_signed(&hostnames)
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
            reoftpd::tls::write_cert_files(&cert_pem, &key_pem, &cert, &key)?;
            println!(
                "Certificate written to {} and key to {}.",
                cert.display(),
                key.display()
            );
        }
    }

    Ok(())
}
