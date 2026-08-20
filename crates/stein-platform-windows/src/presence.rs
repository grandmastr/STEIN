use std::time::Duration;

use stein_core::PresenceState;

/// Content-free signal derived from WTS session lifecycle notifications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresenceSignal {
    Connected,
    Disconnected,
    Logon,
    Logoff,
    Locked,
    Unlocked,
    Ambiguous,
}

/// Why a presence state was emitted. No input details are retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresenceUpdateSource {
    InitialSessionQuery,
    SessionNotification,
    IdleSample,
    ProbeFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PresenceEvent {
    pub state: PresenceState,
    pub source: PresenceUpdateSource,
}

/// Pure fail-closed presence state machine shared by the native adapter and
/// deterministic tests.
#[derive(Clone, Debug)]
pub struct PresenceTracker {
    state: PresenceState,
    may_sample_idle: bool,
    idle_threshold: Duration,
}

impl PresenceTracker {
    pub fn new(idle_threshold: Duration) -> Result<Self, &'static str> {
        if idle_threshold.is_zero() {
            return Err("The idle threshold must be greater than zero.");
        }
        Ok(Self {
            state: PresenceState::Unknown,
            may_sample_idle: false,
            idle_threshold,
        })
    }

    pub fn state(&self) -> PresenceState {
        self.state
    }

    pub fn apply_signal(&mut self, signal: PresenceSignal) -> PresenceState {
        match signal {
            PresenceSignal::Locked => {
                self.may_sample_idle = false;
                self.state = PresenceState::Locked;
            }
            PresenceSignal::Disconnected | PresenceSignal::Logoff => {
                self.may_sample_idle = false;
                self.state = PresenceState::SwitchedAway;
            }
            PresenceSignal::Connected | PresenceSignal::Logon | PresenceSignal::Unlocked => {
                // A reconnect or unlock cannot immediately imply presence. A
                // fresh native idle sample must revalidate it first.
                self.may_sample_idle = true;
                self.state = PresenceState::Unknown;
            }
            PresenceSignal::Ambiguous => {
                self.may_sample_idle = false;
                self.state = PresenceState::Unknown;
            }
        }
        self.state
    }

    pub fn apply_idle_sample(&mut self, idle_for: Result<Duration, ()>) -> PresenceState {
        if !self.may_sample_idle {
            return self.state;
        }
        self.state = match idle_for {
            Ok(duration) if duration >= self.idle_threshold => PresenceState::Idle,
            Ok(_) => PresenceState::Active,
            Err(()) => PresenceState::Unknown,
        };
        self.state
    }
}

#[cfg(windows)]
mod native;

#[cfg(windows)]
pub use native::{PresenceMonitorError, WindowsPresenceMonitor};

#[cfg(windows)]
pub(crate) fn current_native_presence() -> PresenceState {
    native::query_current_presence()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_and_disconnect_cannot_be_overridden_by_idle_samples() {
        let mut tracker = PresenceTracker::new(Duration::from_secs(60)).unwrap();
        tracker.apply_signal(PresenceSignal::Unlocked);
        assert_eq!(
            tracker.apply_idle_sample(Ok(Duration::ZERO)),
            PresenceState::Active
        );

        tracker.apply_signal(PresenceSignal::Locked);
        assert_eq!(
            tracker.apply_idle_sample(Ok(Duration::ZERO)),
            PresenceState::Locked
        );

        tracker.apply_signal(PresenceSignal::Disconnected);
        assert_eq!(
            tracker.apply_idle_sample(Ok(Duration::ZERO)),
            PresenceState::SwitchedAway
        );
    }

    #[test]
    fn unlock_waits_for_fresh_idle_health() {
        let mut tracker = PresenceTracker::new(Duration::from_secs(60)).unwrap();
        tracker.apply_signal(PresenceSignal::Locked);
        assert_eq!(
            tracker.apply_signal(PresenceSignal::Unlocked),
            PresenceState::Unknown
        );
        assert_eq!(
            tracker.apply_idle_sample(Ok(Duration::from_secs(59))),
            PresenceState::Active
        );
        assert_eq!(
            tracker.apply_idle_sample(Ok(Duration::from_secs(60))),
            PresenceState::Idle
        );
    }

    #[test]
    fn ambiguous_session_state_fails_closed() {
        let mut tracker = PresenceTracker::new(Duration::from_secs(60)).unwrap();
        tracker.apply_signal(PresenceSignal::Connected);
        tracker.apply_idle_sample(Ok(Duration::ZERO));
        assert_eq!(tracker.state(), PresenceState::Active);
        assert_eq!(
            tracker.apply_signal(PresenceSignal::Ambiguous),
            PresenceState::Unknown
        );
        assert_eq!(
            tracker.apply_idle_sample(Ok(Duration::ZERO)),
            PresenceState::Unknown
        );
    }

    #[test]
    fn failed_probe_is_unknown_until_a_later_fresh_sample() {
        let mut tracker = PresenceTracker::new(Duration::from_secs(60)).unwrap();
        tracker.apply_signal(PresenceSignal::Unlocked);
        assert_eq!(tracker.apply_idle_sample(Err(())), PresenceState::Unknown);
        assert_eq!(
            tracker.apply_idle_sample(Ok(Duration::ZERO)),
            PresenceState::Active
        );
    }
}
