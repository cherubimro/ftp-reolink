//! TOML config model, parsing, and validation.
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum ConfigError {
    Read(String),
    Parse(String),
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Read(e) => write!(f, "reading config: {e}"),
            ConfigError::Parse(e) => write!(f, "parsing config: {e}"),
            ConfigError::Invalid(e) => write!(f, "invalid config: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerCfg,
    pub archive: ArchiveCfg,
    pub limits: LimitsCfg,
    #[serde(default)]
    pub camera: Vec<CameraCfg>,
    #[serde(default)]
    pub group: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub viewer: Vec<ViewerCfg>,
}

#[derive(Debug, Deserialize)]
pub struct ServerCfg {
    pub listen: String,
    pub port: u16,
    pub passive_ports: [u16; 2],
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    #[serde(default)]
    pub tls_key: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct ArchiveCfg {
    pub root: PathBuf,
    pub retention_days: u64,
}

#[derive(Debug, Deserialize)]
pub struct LimitsCfg {
    pub max_connections: u32,
    pub max_connections_per_ip: u32,
    pub new_conns_per_min_per_ip: u32,
    pub idle_timeout_secs: u64,
    pub min_transfer_rate_bytes_per_sec: u64,
    pub failed_login_lockout: LockoutCfg,
    #[serde(default)]
    pub max_connections_per_account: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct LockoutCfg {
    pub max_attempts: u32,
    pub window_secs: u64,
    pub ban_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct CameraCfg {
    pub name: String,
    #[serde(default)]
    pub username: Option<String>,
    pub upload_password_hash: String,
    #[serde(default)]
    pub require_tls: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ViewerCfg {
    pub name: String,
    pub password_hash: String,
    pub scope: Scope,
}

/// Represents who a viewer can see: all cameras, or a named list of cameras/groups.
///
/// Deserializes from either the string `"all"` or an array of strings like `["outdoor"]`.
/// Uses an intermediate untagged helper enum to handle both TOML representations, then
/// validates that if a string is given it must equal `"all"` (not any arbitrary string).
#[derive(Debug)]
pub enum Scope {
    All,
    List(Vec<String>),
}

// Intermediate helper for untagged deserialization.
// serde's #[serde(untagged)] + #[serde(deserialize_with)] on a unit variant is known
// to not compile reliably, so we use a plain helper enum and a manual impl instead.
#[derive(Deserialize)]
#[serde(untagged)]
enum ScopeRepr {
    Str(String),
    List(Vec<String>),
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match ScopeRepr::deserialize(d)? {
            ScopeRepr::Str(s) if s == "all" => Ok(Scope::All),
            ScopeRepr::Str(s) => Err(serde::de::Error::custom(format!(
                "expected \"all\" or an array of strings, got \"{s}\""
            ))),
            ScopeRepr::List(v) => Ok(Scope::List(v)),
        }
    }
}

impl CameraCfg {
    pub fn login(&self) -> &str {
        self.username.as_deref().unwrap_or(&self.name)
    }
}

pub fn parse_str(s: &str) -> Result<Config, ConfigError> {
    toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))
}

pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let s = std::fs::read_to_string(path).map_err(|e| ConfigError::Read(e.to_string()))?;
    let c = parse_str(&s)?;
    c.validate()?;
    Ok(c)
}

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.passive_ports[0] > self.server.passive_ports[1] {
            return Err(ConfigError::Invalid("passive_ports must be ordered".into()));
        }
        let mut names = BTreeSet::new();
        let mut logins = BTreeSet::new();
        for cam in &self.camera {
            if !names.insert(cam.name.clone()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate camera name {}",
                    cam.name
                )));
            }
            if !logins.insert(cam.login().to_string()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate username {}",
                    cam.login()
                )));
            }
        }
        for (g, members) in &self.group {
            for m in members {
                if !names.contains(m) {
                    return Err(ConfigError::Invalid(format!(
                        "group {g} references unknown camera {m}"
                    )));
                }
            }
        }
        // Viewer names must be unique and must not collide with a camera login,
        // otherwise one account would silently overwrite the other in the
        // login-keyed account map.
        let mut viewer_names = BTreeSet::new();
        for v in &self.viewer {
            if !viewer_names.insert(v.name.clone()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate viewer name {}",
                    v.name
                )));
            }
            if logins.contains(&v.name) {
                return Err(ConfigError::Invalid(format!(
                    "viewer name {} collides with a camera login",
                    v.name
                )));
            }
        }
        for v in &self.viewer {
            if let Scope::List(items) = &v.scope {
                for it in items {
                    if !names.contains(it) && !self.group.contains_key(it) {
                        return Err(ConfigError::Invalid(format!(
                            "viewer {} scope references unknown {it}",
                            v.name
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[server]
listen = "0.0.0.0"
port = 21
passive_ports = [50000, 50100]

[archive]
root = "/srv/reolink"
retention_days = 30

[limits]
max_connections = 256
max_connections_per_ip = 8
new_conns_per_min_per_ip = 30
idle_timeout_secs = 120
min_transfer_rate_bytes_per_sec = 1024
failed_login_lockout = { max_attempts = 5, window_secs = 300, ban_secs = 900 }

[[camera]]
name = "front-door"
upload_password_hash = "$argon2id$x"

[group]
outdoor = ["front-door"]

[[viewer]]
name = "admin"
password_hash = "$argon2id$y"
scope = "all"

[[viewer]]
name = "patio"
password_hash = "$argon2id$z"
scope = ["outdoor"]
"#;

    #[test]
    fn parses_sample() {
        let c = parse_str(SAMPLE).unwrap();
        assert_eq!(c.camera.len(), 1);
        assert_eq!(c.archive.retention_days, 30);
        assert!(matches!(c.viewer[0].scope, Scope::All));
        assert!(matches!(&c.viewer[1].scope, Scope::List(v) if v == &vec!["outdoor".to_string()]));
        c.validate().unwrap();
    }

    #[test]
    fn rejects_scope_referencing_unknown_name() {
        let bad = SAMPLE.replace(r#"scope = ["outdoor"]"#, r#"scope = ["nope"]"#);
        let c = parse_str(&bad).unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_camera_name() {
        let dup = format!(
            "{SAMPLE}\n[[camera]]\nname = \"front-door\"\nupload_password_hash = \"$argon2id$q\"\n"
        );
        let c = parse_str(&dup).unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_bogus_scope_string() {
        let bad = SAMPLE.replace(r#"scope = "all""#, r#"scope = "everything""#);
        assert!(parse_str(&bad).is_err());
    }

    #[test]
    fn rejects_passive_ports_out_of_order() {
        let bad = SAMPLE.replace(
            "passive_ports = [50000, 50100]",
            "passive_ports = [50100, 50000]",
        );
        let c = parse_str(&bad).unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_effective_username() {
        // second camera's username collides with the first camera's effective login ("front-door")
        let dup = format!("{SAMPLE}\n[[camera]]\nname = \"garage\"\nusername = \"front-door\"\nupload_password_hash = \"$argon2id$q\"\n");
        let c = parse_str(&dup).unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_viewer_name() {
        let dup = format!("{SAMPLE}\n[[viewer]]\nname = \"admin\"\npassword_hash = \"$argon2id$dup\"\nscope = \"all\"\n");
        let c = parse_str(&dup).unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_viewer_name_colliding_with_camera_login() {
        let bad = format!("{SAMPLE}\n[[viewer]]\nname = \"front-door\"\npassword_hash = \"$argon2id$c\"\nscope = \"all\"\n");
        let c = parse_str(&bad).unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn max_connections_per_account_defaults_to_none() {
        let c = parse_str(SAMPLE).unwrap();
        assert_eq!(c.limits.max_connections_per_account, None);
    }

    #[test]
    fn max_connections_per_account_parses_when_present() {
        let with = SAMPLE.replace(
            "max_connections_per_ip = 8",
            "max_connections_per_ip = 8\nmax_connections_per_account = 4",
        );
        let c = parse_str(&with).unwrap();
        assert_eq!(c.limits.max_connections_per_account, Some(4));
    }
}
