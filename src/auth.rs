//! libunftp Authenticator + UserDetailProvider backed by argon2id accounts.
//!
//! Implements the `unftp_core::auth` traits:
//! - `ReoAuth` → `Authenticator` (verifies argon2id password, enforces per-account `require_tls`)
//! - `ReoUser` → `UserDetail` + `Display`
//! - `ReoUserProvider` → `UserDetailProvider<User = ReoUser>`
//!
//! Note: `libunftp 0.23` only re-exports `AnonymousAuthenticator` from its `auth` module.
//! The core traits (`Authenticator`, `UserDetail`, `UserDetailProvider`, `Credentials`,
//! `Principal`, `AuthenticationError`, `UserDetailError`, `ChannelEncryptionState`) are
//! in the sibling crate `unftp-core 0.1`, which is used directly here.
use crate::account::{Account, Accounts, Role};
use crate::hashing::verify_password;
use crate::limits::SessionTracker;
use arc_swap::ArcSwap;
use std::sync::Arc;
use unftp_core::auth::{
    AuthenticationError, Authenticator, ChannelEncryptionState, Credentials, Principal, UserDetail,
    UserDetailError, UserDetailProvider,
};

/// Pure credential check — returns the matched account on success.
///
/// Looks up the account by `login`, then verifies `password` against the stored
/// argon2id PHC hash. Returns `None` on any failure (unknown user, wrong
/// password, or hash parse error). This is the security core and is unit-tested directly.
pub fn check_credentials<'a>(
    accounts: &'a Accounts,
    login: &str,
    password: &str,
) -> Option<&'a Account> {
    let acct = accounts.get(login)?;
    match verify_password(password, &acct.password_hash) {
        Ok(true) => Some(acct),
        _ => None,
    }
}

/// Returns `true` when the command channel is TLS-encrypted.
///
/// This small pure helper makes the require_tls gate independently testable
/// without constructing a full async context. Called from `ReoAuth::authenticate`.
///
/// Confirmed variants from `unftp-core 0.1.0/src/auth/authenticator.rs`:
/// - `ChannelEncryptionState::Plaintext` — unencrypted
/// - `ChannelEncryptionState::Tls` — encrypted
pub fn channel_is_secure(state: &ChannelEncryptionState) -> bool {
    matches!(state, ChannelEncryptionState::Tls)
}

/// Per-user detail object returned by `ReoUserProvider` and consumed by libunftp's session layer.
#[derive(Debug, Clone)]
pub struct ReoUser {
    pub login: String,
    pub role: Role,
    pub require_tls: bool,
}

impl std::fmt::Display for ReoUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.login)
    }
}

impl UserDetail for ReoUser {
    fn home(&self) -> Option<&std::path::Path> {
        match &self.role {
            // Uploaders are confined to their jail dir by libunftp's session.
            Role::Uploader { home } => Some(home.as_path()),
            // Viewers' scope is enforced by the storage backend (ScopeMap), which
            // may span multiple roots, so there is no single home() to return.
            Role::Viewer { .. } => None,
        }
    }
}

/// libunftp `Authenticator` backed by argon2id accounts with optional per-account TLS enforcement.
#[derive(Debug)]
pub struct ReoAuth {
    pub accounts: Arc<ArcSwap<Accounts>>,
    pub sessions: Arc<SessionTracker>,
}

#[async_trait::async_trait]
impl Authenticator for ReoAuth {
    async fn authenticate(
        &self,
        username: &str,
        creds: &Credentials,
    ) -> Result<Principal, AuthenticationError> {
        let accts = self.accounts.load_full();
        let password = creds.password.as_deref().unwrap_or("");
        match check_credentials(&accts, username, password) {
            Some(acct) => {
                // Enforce per-account require_tls: reject on a plaintext command
                // channel for accounts that mandate TLS.
                if acct.require_tls && !channel_is_secure(&creds.command_channel_security) {
                    return Err(AuthenticationError::new("TLS required for this account"));
                }
                Ok(Principal {
                    username: username.to_string(),
                })
            }
            None => Err(AuthenticationError::BadPassword),
        }
    }
}

/// libunftp `UserDetailProvider` that maps a `Principal` username → `ReoUser`.
#[derive(Debug)]
pub struct ReoUserProvider {
    pub accounts: Arc<ArcSwap<Accounts>>,
}

#[async_trait::async_trait]
impl UserDetailProvider for ReoUserProvider {
    type User = ReoUser;

    async fn provide_user_detail(&self, principal: &Principal) -> Result<ReoUser, UserDetailError> {
        let accts = self.accounts.load_full();
        match accts.get(&principal.username) {
            Some(a) => Ok(ReoUser {
                login: a.username.clone(),
                role: a.role.clone(),
                require_tls: a.require_tls,
            }),
            None => Err(UserDetailError::UserNotFound {
                username: principal.username.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{Account, Accounts, Role};
    use crate::hashing::hash_password;
    use crate::limits::SessionTracker;
    use arc_swap::ArcSwap;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::Arc;
    use unftp_core::auth::{ChannelEncryptionState, Credentials, Principal, UserDetailProvider};

    fn swap(accts: Accounts) -> Arc<ArcSwap<Accounts>> {
        Arc::new(ArcSwap::from_pointee(accts))
    }

    fn unlimited_tracker() -> Arc<SessionTracker> {
        Arc::new(SessionTracker::new(u32::MAX, None))
    }

    fn accounts_with(login: &str, plain: &str, require_tls: bool) -> Accounts {
        let mut by_login = BTreeMap::new();
        by_login.insert(
            login.to_string(),
            Account {
                username: login.to_string(),
                password_hash: hash_password(plain).unwrap(),
                role: Role::Uploader {
                    home: PathBuf::from("/srv/reolink/x"),
                },
                require_tls,
            },
        );
        Accounts { by_login }
    }

    // TDD RED phase evidence: these two tests were written before the implementation existed.
    // They test the pure credential-check core.

    #[test]
    fn accepts_correct_password() {
        let a = accounts_with("cam", "pw", false);
        assert!(check_credentials(&a, "cam", "pw").is_some());
    }

    #[test]
    fn rejects_wrong_password_and_unknown_user() {
        let a = accounts_with("cam", "pw", false);
        assert!(check_credentials(&a, "cam", "nope").is_none());
        assert!(check_credentials(&a, "ghost", "pw").is_none());
    }

    /// channel_is_secure() must return false for Plaintext and true for Tls.
    /// Tests the pure helper that the require_tls gate delegates to.
    #[test]
    fn channel_is_secure_variants() {
        assert!(!channel_is_secure(&ChannelEncryptionState::Plaintext));
        assert!(channel_is_secure(&ChannelEncryptionState::Tls));
    }

    /// require_tls=true account: Plaintext channel → Err, Tls channel → Ok(Principal).
    /// This is the real async integration test of the TLS gate end-to-end.
    #[tokio::test]
    async fn require_tls_rejects_plaintext_accepts_secure() {
        let auth = ReoAuth {
            accounts: swap(accounts_with("cam", "pw", true)),
            sessions: unlimited_tracker(),
        };

        let plaintext_creds = Credentials {
            password: Some("pw".to_string()),
            certificate_chain: None,
            source_ip: "127.0.0.1".parse().unwrap(),
            command_channel_security: ChannelEncryptionState::Plaintext,
        };

        let secure_creds = Credentials {
            password: Some("pw".to_string()),
            certificate_chain: None,
            source_ip: "127.0.0.1".parse().unwrap(),
            command_channel_security: ChannelEncryptionState::Tls,
        };

        // require_tls=true + plaintext → authentication error
        let result = auth.authenticate("cam", &plaintext_creds).await;
        assert!(
            result.is_err(),
            "expected Err for plaintext channel with require_tls=true"
        );

        // require_tls=true + TLS → success with correct username
        let result = auth.authenticate("cam", &secure_creds).await;
        assert!(
            result.is_ok(),
            "expected Ok for TLS channel with require_tls=true, got: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().username, "cam");
    }

    /// require_tls=false account: plaintext channel should succeed.
    #[tokio::test]
    async fn no_require_tls_allows_plaintext() {
        let auth = ReoAuth {
            accounts: swap(accounts_with("cam", "pw", false)),
            sessions: unlimited_tracker(),
        };

        let plaintext_creds = Credentials {
            password: Some("pw".to_string()),
            certificate_chain: None,
            source_ip: "127.0.0.1".parse().unwrap(),
            command_channel_security: ChannelEncryptionState::Plaintext,
        };

        let result = auth.authenticate("cam", &plaintext_creds).await;
        assert!(
            result.is_ok(),
            "expected Ok for plaintext with require_tls=false, got: {:?}",
            result.err()
        );
    }

    /// ReoUser::home() returns Some for Uploader and None for Viewer.
    #[test]
    fn reo_user_home_returns_correct_values() {
        use crate::paths::ScopeMap;

        let uploader = ReoUser {
            login: "cam".to_string(),
            role: Role::Uploader {
                home: PathBuf::from("/srv/reolink/x"),
            },
            require_tls: false,
        };
        assert_eq!(
            uploader.home(),
            Some(std::path::Path::new("/srv/reolink/x"))
        );

        let viewer = ReoUser {
            login: "viewer".to_string(),
            role: Role::Viewer {
                scope: ScopeMap::single(PathBuf::from("/srv/reolink")),
            },
            require_tls: false,
        };
        assert_eq!(viewer.home(), None);
    }

    /// ReoUserProvider returns ReoUser for known principal, UserNotFound for unknown.
    #[tokio::test]
    async fn user_detail_provider_known_and_unknown() {
        let provider = ReoUserProvider {
            accounts: swap(accounts_with("cam", "pw", false)),
        };
        let principal = Principal {
            username: "cam".to_string(),
        };
        let user = provider.provide_user_detail(&principal).await.unwrap();
        assert_eq!(user.login, "cam");

        let unknown = Principal {
            username: "ghost".to_string(),
        };
        let err = provider.provide_user_detail(&unknown).await.unwrap_err();
        assert!(matches!(err, UserDetailError::UserNotFound { .. }));
    }
}
