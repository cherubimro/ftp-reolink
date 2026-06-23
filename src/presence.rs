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
            PresenceEvent::LoggedIn => self.tracker.on_login(&m.username),
            PresenceEvent::LoggedOut => self.tracker.on_logout(&m.username),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TDD RED: written before implementation to verify login/logout adjusts tracker counts.
    #[tokio::test]
    async fn login_then_logout_adjusts_tracker() {
        let tracker = Arc::new(SessionTracker::new(1, None));
        let l = ReoPresenceListener {
            tracker: tracker.clone(),
        };
        let meta = EventMeta {
            username: "cam".into(),
            trace_id: "t".into(),
            sequence_number: 0,
        };
        l.receive_presence_event(PresenceEvent::LoggedIn, meta.clone())
            .await;
        assert!(tracker.at_capacity("other")); // global 1 >= 1
        l.receive_presence_event(PresenceEvent::LoggedOut, meta)
            .await;
        assert!(!tracker.at_capacity("other")); // global back to 0
    }

    /// A second LoggedIn event for the same user increments the per-account counter.
    #[tokio::test]
    async fn two_logins_increments_per_account() {
        let tracker = Arc::new(SessionTracker::new(100, Some(1)));
        let l = ReoPresenceListener {
            tracker: tracker.clone(),
        };
        let meta = EventMeta {
            username: "cam".into(),
            trace_id: "t1".into(),
            sequence_number: 0,
        };
        l.receive_presence_event(PresenceEvent::LoggedIn, meta.clone())
            .await;
        // After first login, "cam" is at per-account capacity.
        assert!(tracker.at_capacity("cam"));
        // After logout, capacity frees up.
        l.receive_presence_event(PresenceEvent::LoggedOut, meta)
            .await;
        assert!(!tracker.at_capacity("cam"));
    }
}
