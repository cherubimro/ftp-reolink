//! Resolve config into login-keyed accounts with roles and scopes.
use crate::config::{Config, Scope};
use crate::paths::ScopeMap;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum Role {
    Uploader { home: PathBuf },
    Viewer { scope: ScopeMap },
}

#[derive(Debug, Clone)]
pub struct Account {
    pub username: String,
    pub password_hash: String,
    pub role: Role,
    pub require_tls: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Accounts {
    pub by_login: BTreeMap<String, Account>,
}

impl Accounts {
    pub fn get(&self, login: &str) -> Option<&Account> {
        self.by_login.get(login)
    }
}

fn expand_scope(cfg: &Config, scope: &Scope) -> ScopeMap {
    let root = &cfg.archive.root;
    match scope {
        Scope::All => ScopeMap::single(root.clone()),
        Scope::List(items) => {
            let mut names: BTreeSet<String> = BTreeSet::new();
            for it in items {
                if let Some(members) = cfg.group.get(it) {
                    names.extend(members.iter().cloned());
                } else {
                    names.insert(it.clone());
                }
            }
            let mut roots = BTreeMap::new();
            for n in names {
                roots.insert(n.clone(), root.join(&n));
            }
            ScopeMap::multi(roots)
        }
    }
}

pub fn build(cfg: &Config) -> Accounts {
    let mut by_login = BTreeMap::new();
    for cam in &cfg.camera {
        let login = cam.login().to_string();
        by_login.insert(
            login.clone(),
            Account {
                username: login,
                password_hash: cam.upload_password_hash.clone(),
                role: Role::Uploader { home: cfg.archive.root.join(&cam.name) },
                require_tls: cam.require_tls.unwrap_or(false),
            },
        );
    }
    for v in &cfg.viewer {
        by_login.insert(
            v.name.clone(),
            Account {
                username: v.name.clone(),
                password_hash: v.password_hash.clone(),
                role: Role::Viewer { scope: expand_scope(cfg, &v.scope) },
                require_tls: false,
            },
        );
    }
    Accounts { by_login }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;

    const CFG: &str = r#"
[server]
listen = "0.0.0.0"
port = 21
passive_ports = [50000, 50100]
[archive]
root = "/srv/reolink"
retention_days = 30
[limits]
max_connections = 1
max_connections_per_ip = 1
new_conns_per_min_per_ip = 1
idle_timeout_secs = 1
min_transfer_rate_bytes_per_sec = 1
failed_login_lockout = { max_attempts = 1, window_secs = 1, ban_secs = 1 }
[[camera]]
name = "front-door"
username = "cam-fd"
upload_password_hash = "$argon2id$x"
require_tls = true
[[camera]]
name = "driveway"
upload_password_hash = "$argon2id$y"
[group]
outdoor = ["driveway"]
[[viewer]]
name = "admin"
password_hash = "$argon2id$z"
scope = "all"
[[viewer]]
name = "patio"
password_hash = "$argon2id$w"
scope = ["outdoor", "front-door"]
"#;

    #[test]
    fn uploader_login_uses_username_override() {
        let cfg = parse_str(CFG).unwrap();
        let accts = build(&cfg);
        let a = accts.get("cam-fd").expect("login cam-fd");
        assert!(a.require_tls);
        match &a.role {
            Role::Uploader { home } => assert!(home.ends_with("front-door")),
            _ => panic!("expected uploader"),
        }
    }

    #[test]
    fn uploader_defaults_login_to_name() {
        let cfg = parse_str(CFG).unwrap();
        let accts = build(&cfg);
        assert!(accts.get("driveway").is_some());
    }

    #[test]
    fn viewer_all_is_single_root() {
        let cfg = parse_str(CFG).unwrap();
        let accts = build(&cfg);
        let a = accts.get("admin").unwrap();
        assert!(matches!(a.role, Role::Viewer { .. }));
    }

    #[test]
    fn viewer_scope_expands_group_and_camera_deduped() {
        let cfg = parse_str(CFG).unwrap();
        let accts = build(&cfg);
        let a = accts.get("patio").unwrap();
        if let Role::Viewer { scope } = &a.role {
            let mut names = scope.list_root();
            names.sort();
            assert_eq!(names, vec!["driveway".to_string(), "front-door".to_string()]);
        } else {
            panic!("expected viewer");
        }
    }
}
