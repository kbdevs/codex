use std::time::Duration;
use std::time::Instant;

use super::*;

#[test]
fn records_delta_and_formats_tokens_per_second() {
    let start = Instant::now();
    let mut meter = LiveTpsMeter::default();

    meter.record_delta("1234567890123456789012345678901234567890", start);

    assert_eq!(
        meter.display(start + Duration::from_secs(1)),
        Some("10.0 tps".to_string())
    );
}

#[test]
fn reset_clears_display_value() {
    let start = Instant::now();
    let mut meter = LiveTpsMeter::default();
    meter.record_delta("12345678", start);

    meter.reset();

    assert_eq!(meter.display(start + Duration::from_secs(1)), None);
}

#[test]
fn empty_deltas_do_not_start_meter() {
    let start = Instant::now();
    let mut meter = LiveTpsMeter::default();

    meter.record_delta("", start);

    assert_eq!(meter.display(start + Duration::from_secs(1)), None);
}
