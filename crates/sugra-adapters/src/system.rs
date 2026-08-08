//! Operating-system clock boundary.

use sugra_core::Clock;
use time::OffsetDateTime;

/// UTC clock backed by the operating system.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}
