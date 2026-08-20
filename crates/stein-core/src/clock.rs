use std::sync::Mutex;
use std::time::{Duration, Instant};

use time::OffsetDateTime;

/// Time is an injected boundary so freshness, expiry, cooldown, and recovery
/// behavior can be replayed deterministically.
pub trait Clock: Send + Sync {
    fn now_utc(&self) -> OffsetDateTime;
    fn monotonic_elapsed(&self) -> Duration;
}

#[derive(Debug)]
pub struct SystemClock {
    started: Instant,
}

impl Default for SystemClock {
    fn default() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn now_utc(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    fn monotonic_elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

#[derive(Debug)]
pub struct ManualClock {
    state: Mutex<ManualClockState>,
}

#[derive(Clone, Copy, Debug)]
struct ManualClockState {
    utc: OffsetDateTime,
    elapsed: Duration,
}

impl ManualClock {
    pub fn new(utc: OffsetDateTime) -> Self {
        Self {
            state: Mutex::new(ManualClockState {
                utc,
                elapsed: Duration::ZERO,
            }),
        }
    }

    pub fn advance(&self, duration: Duration) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.utc += time::Duration::try_from(duration).unwrap_or(time::Duration::MAX);
        state.elapsed = state.elapsed.saturating_add(duration);
    }

    pub fn set_utc(&self, utc: OffsetDateTime) {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .utc = utc;
    }
}

impl Clock for ManualClock {
    fn now_utc(&self) -> OffsetDateTime {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .utc
    }

    fn monotonic_elapsed(&self) -> Duration {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .elapsed
    }
}
