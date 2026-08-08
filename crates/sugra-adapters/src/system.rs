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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_returns_the_current_utc_time() {
        let before = OffsetDateTime::now_utc();
        let observed = SystemClock.now();
        let after = OffsetDateTime::now_utc();

        assert!(observed >= before);
        assert!(observed <= after);
        assert_eq!(observed.offset(), time::UtcOffset::UTC);
    }
}
