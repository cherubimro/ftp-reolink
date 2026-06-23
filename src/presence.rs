//! Connection accountant: maintains live session counts from libunftp presence
//! events (the only hook that sees both ends of a session, keyed by username).
use crate::limits::SessionTracker;
use libunftp::notification::{EventMeta, PresenceEvent, PresenceListener};
use std::sync::Arc;

#[derive(Debug)]
pub struct ReoPresenceListener {
    pub tracker: Arc<SessionTracker>,
}

#[async_trait::async_trait]
impl PresenceListener for ReoPresenceListener {
    async fn receive_presence_event(&self, e: PresenceEvent, m: EventMeta) {
        match e {
            // Admission is counted atomically at the auth gate (try_admit);
            // LoggedIn must NOT increment again here or sessions double-count.
            PresenceEvent::LoggedIn => {}
            PresenceEvent::LoggedOut => self.tracker.on_logout(&m.username),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// After try_admit sets the count, LoggedOut decrements it correctly.
    /// LoggedIn is now a no-op in the presence listener (admission happens at the auth gate).
    #[tokio::test]
    async fn logout_decrements_tracker_admitted_via_try_admit() {
        let tracker = Arc::new(SessionTracker::new(1, None));
        let l = ReoPresenceListener {
            tracker: tracker.clone(),
        };
        let meta = EventMeta {
            username: "cam".into(),
            trace_id: "t".into(),
            sequence_number: 0,
        };
        // Simulate what the auth gate does: atomically admit.
        assert!(tracker.try_admit("cam")); // global 0 -> 1
        assert!(tracker.at_capacity("other")); // global 1 >= 1

        // LoggedIn is a no-op; must NOT double-count.
        l.receive_presence_event(PresenceEvent::LoggedIn, meta.clone())
            .await;
        assert!(tracker.at_capacity("other")); // still 1, not 2

        // LoggedOut must decrement.
        l.receive_presence_event(PresenceEvent::LoggedOut, meta)
            .await;
        assert!(!tracker.at_capacity("other")); // global back to 0
    }

    /// LoggedOut decrements per-account cap correctly after try_admit.
    #[tokio::test]
    async fn logout_decrements_per_account_cap() {
        let tracker = Arc::new(SessionTracker::new(100, Some(1)));
        let l = ReoPresenceListener {
            tracker: tracker.clone(),
        };
        let meta = EventMeta {
            username: "cam".into(),
            trace_id: "t1".into(),
            sequence_number: 0,
        };
        // Admit via the gate (as auth would do).
        assert!(tracker.try_admit("cam"));
        assert!(tracker.at_capacity("cam")); // per-account cap 1

        // After logout, capacity frees up.
        l.receive_presence_event(PresenceEvent::LoggedOut, meta)
            .await;
        assert!(!tracker.at_capacity("cam"));
    }
}
