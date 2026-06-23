//! CLI argument model and config-snippet renderers.
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "reoftpd")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start the FTP server.
    Serve {
        #[arg(long, default_value = "/etc/reoftpd/reoftpd.toml")]
        config: PathBuf,
    },
    /// Run the retention sweep once and exit.
    Cleanup {
        #[arg(long, default_value = "/etc/reoftpd/reoftpd.toml")]
        config: PathBuf,
        /// Print what would be deleted without deleting anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Register a new camera account (appends to config).
    AddCamera {
        name: String,
        #[arg(long)]
        username: Option<String>,
        /// Require TLS for this camera's uploads.
        #[arg(long)]
        require_tls: bool,
    },
    /// Register a new viewer account (appends to config).
    AddViewer {
        name: String,
        /// Scope: "all" or comma-separated list of camera names/groups.
        #[arg(long)]
        scope: String,
    },
    /// Hash a password and print the PHC string.
    HashPassword,
    /// Print an nftables ruleset (per-IP + global connection caps) from the config
    Nftables {
        #[arg(long, default_value = "/etc/reoftpd/reoftpd.toml")]
        config: std::path::PathBuf,
    },
    /// Generate a self-signed TLS certificate and key.
    Gencert {
        #[arg(long, num_args = 1..)]
        hostnames: Vec<String>,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        key: PathBuf,
    },
    /// Generate an age keypair (public recipient -> config; private identity -> off-server)
    Genkey {
        #[arg(long)]
        output: Option<std::path::PathBuf>,
    },
    /// Decrypt downloaded *.age files locally with your age identity
    Decrypt {
        #[arg(long)]
        identity: std::path::PathBuf,
        #[arg(long)]
        output: Option<std::path::PathBuf>,
        /// One or more downloaded *.age files to decrypt
        #[arg(required = true)]
        files: Vec<std::path::PathBuf>,
    },
}

/// Render a `[[camera]]` TOML snippet suitable for appending to the config file.
///
/// Only includes `username` if it differs from the default (i.e., if `Some`).
/// Only includes `require_tls` when `true`.
pub fn render_camera_entry(
    name: &str,
    username: Option<&str>,
    hash: &str,
    require_tls: bool,
) -> String {
    let mut s = format!("\n[[camera]]\nname = \"{name}\"\n");
    if let Some(u) = username {
        s.push_str(&format!("username = \"{u}\"\n"));
    }
    s.push_str(&format!("upload_password_hash = \"{hash}\"\n"));
    if require_tls {
        s.push_str("require_tls = true\n");
    }
    s
}

/// Render a `[[viewer]]` TOML snippet suitable for appending to the config file.
///
/// `scope` is either `"all"` (serialised as a TOML string) or a comma-separated
/// list of camera/group names (serialised as a TOML array of strings).
pub fn render_viewer_entry(name: &str, hash: &str, scope: &str) -> String {
    let scope_toml = if scope == "all" {
        "\"all\"".to_string()
    } else {
        let items: Vec<String> = scope
            .split(',')
            .map(|x| format!("\"{}\"", x.trim()))
            .collect();
        format!("[{}]", items.join(", "))
    };
    format!("\n[[viewer]]\nname = \"{name}\"\npassword_hash = \"{hash}\"\nscope = {scope_toml}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn camera_entry_includes_username_and_tls() {
        let s = render_camera_entry("front-door", Some("cam-fd"), "$argon2id$x", true);
        assert!(s.contains("name = \"front-door\""));
        assert!(s.contains("username = \"cam-fd\""));
        assert!(s.contains("require_tls = true"));
        assert!(s.contains("upload_password_hash = \"$argon2id$x\""));
    }

    #[test]
    fn camera_entry_omits_username_when_default() {
        let s = render_camera_entry("driveway", None, "$argon2id$y", false);
        assert!(!s.contains("username ="));
        assert!(!s.contains("require_tls"));
    }

    #[test]
    fn viewer_entry_all_scope() {
        let s = render_viewer_entry("admin", "$argon2id$z", "all");
        assert!(s.contains("scope = \"all\""));
    }

    #[test]
    fn viewer_entry_list_scope() {
        let s = render_viewer_entry("patio", "$argon2id$w", "outdoor,front-door");
        assert!(s.contains(r#"scope = ["outdoor", "front-door"]"#));
    }
}
