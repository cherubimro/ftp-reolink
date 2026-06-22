//! Connection caps (DoS resistance).
//!
//! `ConnTracker`/`ConnGuard` are intentionally staged: libunftp 0.23 exposes no
//! per-connection accept hook through the public `listen` API, so they are not
//! yet wired. Brute-force lockout is handled by libunftp's built-in
//! `failed_logins_policy` (wired in `server.rs`).
use crate::config::LimitsCfg;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

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
            state: Arc::new(Mutex::new(ConnState {
                global: 0,
                per_ip: HashMap::new(),
            })),
        }
    }

    pub fn try_acquire(&self, ip: IpAddr) -> Option<ConnGuard> {
        let mut s = self.state.lock().unwrap();
        if s.global >= self.max_global {
            return None;
        }
        let current = s.per_ip.get(&ip).copied().unwrap_or(0);
        if current >= self.max_per_ip {
            return None;
        }
        *s.per_ip.entry(ip).or_insert(0) += 1;
        s.global += 1;
        Some(ConnGuard {
            ip,
            state: Arc::clone(&self.state),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

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
}
