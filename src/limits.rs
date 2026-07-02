//! Concurrent-session limits (global + per-account). Per-IP caps are enforced
//! at the firewall (see `nftables.rs`), not here — libunftp 0.23 gives no peer
//! IP at session end.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How often the background reaper sweeps for stale sessions.
pub const REAP_INTERVAL_SECS: u64 = 60;
/// Sessions admitted longer ago than this are reclaimed. Set well above a
/// normal session (idle control connections close at `idle_timeout_secs`, ~120s;
/// clip downloads finish in seconds), so in practice this only reclaims slots
/// leaked by unclean disconnects — where libunftp fires no LoggedOut. Reaping a
/// still-live session is harmless: it frees the slot early, the transfer runs on.
pub const SESSION_TTL_SECS: u64 = 300;

#[derive(Debug)]
struct SessionState {
    // One admit timestamp per live session, grouped by account. A vec's length
    // is that account's live session count. Timestamps let `reap` reclaim slots
    // whose connection died uncleanly (no libunftp LoggedOut event fired).
    per_account: HashMap<String, Vec<Instant>>,
    global: u32,
    max_global: u32,
    max_per_account: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct SessionTracker {
    state: Arc<Mutex<SessionState>>,
}

impl SessionTracker {
    pub fn new(max_global: u32, max_per_account: Option<u32>) -> Self {
        SessionTracker {
            state: Arc::new(Mutex::new(SessionState {
                global: 0,
                per_account: HashMap::new(),
                max_global,
                max_per_account,
            })),
        }
    }

    pub fn on_login(&self, username: &str) {
        let mut s = self.state.lock().unwrap();
        s.per_account
            .entry(username.to_string())
            .or_default()
            .push(Instant::now());
        s.global = s.global.saturating_add(1);
    }

    pub fn on_logout(&self, username: &str) {
        let mut s = self.state.lock().unwrap();
        let mut removed = false;
        if let Some(v) = s.per_account.get_mut(username) {
            if !v.is_empty() {
                v.remove(0); // drop the oldest session for this account
                removed = true;
            }
        }
        if removed {
            s.global = s.global.saturating_sub(1);
        }
        if s.per_account.get(username).is_some_and(|v| v.is_empty()) {
            s.per_account.remove(username);
        }
    }

    /// Reclaim sessions admitted longer than `ttl` ago and decrement the counts.
    /// This is the backstop for slots leaked by unclean disconnects, where
    /// libunftp never emits LoggedOut. Reaping a still-live session is safe: it
    /// only frees a slot early (the transfer keeps running). Returns the count
    /// reaped so the caller can log it.
    pub fn reap(&self, ttl: Duration) -> u32 {
        let mut s = self.state.lock().unwrap();
        let now = Instant::now();
        let mut reaped = 0u32;
        s.per_account.retain(|_, v| {
            let before = v.len();
            v.retain(|t| now.duration_since(*t) < ttl);
            reaped += (before - v.len()) as u32;
            !v.is_empty()
        });
        s.global = s.global.saturating_sub(reaped);
        reaped
    }

    pub fn at_capacity(&self, username: &str) -> bool {
        let s = self.state.lock().unwrap();
        if s.global >= s.max_global {
            return true;
        }
        match s.max_per_account {
            Some(m) => s.per_account.get(username).map_or(0, |v| v.len() as u32) >= m,
            None => false,
        }
    }

    /// Atomically admit a session if under both caps: on success increments the
    /// global and per-account counts and returns true; at capacity, returns
    /// false WITHOUT mutating. Checking and reserving under one lock closes the
    /// check-then-increment race that a separate at_capacity()+on_login() had.
    pub fn try_admit(&self, username: &str) -> bool {
        let mut s = self.state.lock().unwrap();
        if s.global >= s.max_global {
            return false;
        }
        if let Some(m) = s.max_per_account {
            if s.per_account.get(username).map_or(0, |v| v.len() as u32) >= m {
                return false;
            }
        }
        s.per_account
            .entry(username.to_string())
            .or_default()
            .push(Instant::now());
        s.global = s.global.saturating_add(1);
        true
    }

    pub fn set_limits(&self, max_global: u32, max_per_account: Option<u32>) {
        let mut s = self.state.lock().unwrap();
        s.max_global = max_global;
        s.max_per_account = max_per_account;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_cap_blocks_when_reached() {
        let t = SessionTracker::new(2, None);
        t.on_login("a");
        t.on_login("b");
        assert!(t.at_capacity("c")); // global 2 >= 2
        t.on_logout("a");
        assert!(!t.at_capacity("c")); // global 1 < 2
    }

    #[test]
    fn per_account_cap_blocks_same_user_only() {
        let t = SessionTracker::new(100, Some(1));
        t.on_login("a");
        assert!(t.at_capacity("a")); // a has 1 >= 1
        assert!(!t.at_capacity("b")); // b has 0
    }

    #[test]
    fn logout_saturates_and_never_underflows() {
        let t = SessionTracker::new(5, Some(2));
        t.on_logout("ghost"); // no prior login
        assert!(!t.at_capacity("ghost"));
        t.on_login("ghost");
        t.on_logout("ghost");
        t.on_logout("ghost"); // extra logout must not underflow
        assert!(!t.at_capacity("ghost"));
    }

    #[test]
    fn unlimited_per_account_when_none() {
        let t = SessionTracker::new(100, None);
        t.on_login("a");
        t.on_login("a");
        t.on_login("a");
        assert!(!t.at_capacity("a")); // per-account unlimited; global 3 < 100
    }

    #[test]
    fn set_limits_updates_caps_live() {
        let t = SessionTracker::new(1, None);
        t.on_login("a");
        assert!(t.at_capacity("b")); // global 1 >= 1
        t.set_limits(2, None);
        assert!(!t.at_capacity("b")); // global 1 < 2
    }

    #[test]
    fn try_admit_increments_on_success_and_blocks_at_cap() {
        let t = SessionTracker::new(1, None);
        assert!(t.try_admit("a")); // 0 -> 1, admitted
        assert!(!t.try_admit("b")); // global 1 >= 1, refused
        t.on_logout("a"); // 1 -> 0
        assert!(t.try_admit("b")); // now admitted
    }

    #[test]
    fn try_admit_does_not_increment_when_refused() {
        let t = SessionTracker::new(1, None);
        assert!(t.try_admit("a"));
        assert!(!t.try_admit("a")); // refused
        assert!(!t.try_admit("a")); // still refused; the refusals must not have incremented
        t.on_logout("a");
        assert!(t.try_admit("a")); // exactly one slot freed -> admit succeeds
    }

    #[test]
    fn try_admit_respects_per_account_cap() {
        let t = SessionTracker::new(100, Some(1));
        assert!(t.try_admit("a"));
        assert!(!t.try_admit("a")); // per-account cap 1
        assert!(t.try_admit("b")); // different account ok
    }

    #[test]
    fn reap_frees_stale_leaked_sessions() {
        // Simulates a session admitted at the auth gate whose connection died
        // uncleanly (no LoggedOut) — the slot must be reclaimable by age.
        let t = SessionTracker::new(100, Some(1));
        assert!(t.try_admit("a"));
        assert!(!t.try_admit("a")); // at per-account cap, leaked slot blocks re-login
        let reaped = t.reap(Duration::from_secs(0)); // ttl 0 => everything is stale
        assert_eq!(reaped, 1);
        assert!(t.try_admit("a")); // slot reclaimed
    }

    #[test]
    fn reap_keeps_fresh_sessions() {
        let t = SessionTracker::new(100, Some(2));
        assert!(t.try_admit("a"));
        assert_eq!(t.reap(Duration::from_secs(3600)), 0); // fresh, not reaped
        assert!(t.try_admit("a")); // still counted: this is the 2nd slot
        assert!(!t.try_admit("a")); // now at cap 2 -> fresh sessions survived reap
    }

    #[test]
    fn reap_decrements_global_too() {
        let t = SessionTracker::new(1, None);
        assert!(t.try_admit("a")); // global 1/1
        assert!(!t.try_admit("b")); // global full
        assert_eq!(t.reap(Duration::from_secs(0)), 1);
        assert!(t.try_admit("b")); // global slot reclaimed
    }
}
