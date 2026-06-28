use std::time::Duration;
use std::time::Instant;

const CHARS_PER_TOKEN: f64 = 4.0;
const MIN_RATE_WINDOW: Duration = Duration::from_millis(250);

#[derive(Debug, Default)]
pub(super) struct LiveTpsMeter {
    started_at: Option<Instant>,
    estimated_tokens: f64,
}

impl LiveTpsMeter {
    pub(super) fn reset(&mut self) {
        *self = Self::default();
    }

    pub(super) fn record_delta(&mut self, delta: &str, now: Instant) {
        if delta.is_empty() {
            return;
        }

        if self.started_at.is_none() {
            self.started_at = Some(now);
        }
        self.estimated_tokens += estimate_tokens(delta);
    }

    pub(super) fn display(&self, now: Instant) -> Option<String> {
        let started_at = self.started_at?;
        if self.estimated_tokens <= 0.0 {
            return None;
        }

        let elapsed = now
            .saturating_duration_since(started_at)
            .max(MIN_RATE_WINDOW)
            .as_secs_f64();
        let tokens_per_second = self.estimated_tokens / elapsed;
        if tokens_per_second < 100.0 {
            Some(format!("{tokens_per_second:.1} tps"))
        } else {
            Some(format!("{tokens_per_second:.0} tps"))
        }
    }
}

fn estimate_tokens(delta: &str) -> f64 {
    delta.chars().count() as f64 / CHARS_PER_TOKEN
}

#[cfg(test)]
#[path = "live_tps_tests.rs"]
mod tests;
