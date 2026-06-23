//! Concurrent-session limits (global + per-account). Per-IP caps are enforced
//! at the firewall (see `nftables.rs`), not here — libunftp 0.23 gives no peer
//! IP at session end.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct SessionState {
    global: u32,
    per_account: HashMap<String, u32>,
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
        s.global = s.global.saturating_add(1);
        let c = s.per_account.entry(username.to_string()).or_insert(0);
        *c = c.saturating_add(1);
    }

    pub fn on_logout(&self, username: &str) {
        let mut s = self.state.lock().unwrap();
        s.global = s.global.saturating_sub(1);
        if let Some(c) = s.per_account.get_mut(username) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                s.per_account.remove(username);
            }
        }
    }

    pub fn at_capacity(&self, username: &str) -> bool {
        let s = self.state.lock().unwrap();
        if s.global >= s.max_global {
            return true;
        }
        match s.max_per_account {
            Some(m) => s.per_account.get(username).copied().unwrap_or(0) >= m,
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
            if s.per_account.get(username).copied().unwrap_or(0) >= m {
                return false;
            }
        }
        s.global = s.global.saturating_add(1);
        let c = s.per_account.entry(username.to_string()).or_insert(0);
        *c = c.saturating_add(1);
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
}
