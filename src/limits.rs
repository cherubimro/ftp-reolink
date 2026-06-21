//! Connection caps and login-failure lockout (DoS resistance).
use crate::config::{LimitsCfg, LockoutCfg};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct ConnState {
    global: u32,
    per_ip: HashMap<IpAddr, u32>,
}

#[derive(Debug, Clone)]
pub struct ConnTracker {
    max_global: u32,
    max_per_ip: u32,
    state: Arc<Mutex<ConnState>>,
}

pub struct ConnGuard {
    ip: IpAddr,
    state: Arc<Mutex<ConnState>>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut s = self.state.lock().unwrap();
        s.global = s.global.saturating_sub(1);
        if let Some(c) = s.per_ip.get_mut(&self.ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                s.per_ip.remove(&self.ip);
            }
        }
    }
}

impl ConnTracker {
    pub fn new(cfg: &LimitsCfg) -> Self {
        Self::new_raw(cfg.max_connections, cfg.max_connections_per_ip)
    }

    pub fn new_raw(max_global: u32, max_per_ip: u32) -> Self {
        ConnTracker {
            max_global,
            max_per_ip,
            state: Arc::new(Mutex::new(ConnState { global: 0, per_ip: HashMap::new() })),
        }
    }

    pub fn try_acquire(&self, ip: IpAddr) -> Option<ConnGuard> {
        let mut s = self.state.lock().unwrap();
        if s.global >= self.max_global {
            return None;
        }
        let entry = s.per_ip.entry(ip).or_insert(0);
        if *entry >= self.max_per_ip {
            return None;
        }
        *entry += 1;
        s.global += 1;
        Some(ConnGuard { ip, state: Arc::clone(&self.state) })
    }
}

#[derive(Debug, Clone)]
pub struct LoginTracker {
    max_attempts: u32,
    window: Duration,
    ban: Duration,
    state: Arc<Mutex<HashMap<IpAddr, (u32, Instant, Option<Instant>)>>>,
}

impl LoginTracker {
    pub fn new(cfg: &LockoutCfg) -> Self {
        Self::new_raw(
            cfg.max_attempts,
            Duration::from_secs(cfg.window_secs),
            Duration::from_secs(cfg.ban_secs),
        )
    }

    pub fn new_raw(max_attempts: u32, window: Duration, ban: Duration) -> Self {
        LoginTracker {
            max_attempts,
            window,
            ban,
            state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn record_failure(&self, ip: IpAddr, now: Instant) {
        let mut s = self.state.lock().unwrap();
        let entry = s.entry(ip).or_insert((0, now, None));
        if now.duration_since(entry.1) > self.window {
            *entry = (0, now, None);
        }
        entry.0 += 1;
        if entry.0 >= self.max_attempts {
            entry.2 = Some(now);
        }
    }

    pub fn is_banned(&self, ip: IpAddr, now: Instant) -> bool {
        let s = self.state.lock().unwrap();
        if let Some((_, _, Some(since))) = s.get(&ip) {
            now.duration_since(*since) <= self.ban
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    fn ip(n: u8) -> IpAddr { IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)) }

    #[test]
    fn per_ip_cap_blocks_extra_connection() {
        let t = ConnTracker::new_raw(10, 2);
        let _g1 = t.try_acquire(ip(1)).unwrap();
        let _g2 = t.try_acquire(ip(1)).unwrap();
        assert!(t.try_acquire(ip(1)).is_none());
        // a different IP still gets a slot
        assert!(t.try_acquire(ip(2)).is_some());
    }

    #[test]
    fn dropping_guard_frees_slot() {
        let t = ConnTracker::new_raw(10, 1);
        {
            let _g = t.try_acquire(ip(1)).unwrap();
            assert!(t.try_acquire(ip(1)).is_none());
        }
        assert!(t.try_acquire(ip(1)).is_some());
    }

    #[test]
    fn lockout_after_threshold_then_expires() {
        let t = LoginTracker::new_raw(2, Duration::from_secs(300), Duration::from_secs(900));
        let now = Instant::now();
        assert!(!t.is_banned(ip(1), now));
        t.record_failure(ip(1), now);
        t.record_failure(ip(1), now);
        assert!(t.is_banned(ip(1), now));
        // after ban window
        assert!(!t.is_banned(ip(1), now + Duration::from_secs(901)));
    }
}
