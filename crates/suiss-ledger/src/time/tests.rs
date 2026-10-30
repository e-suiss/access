use super::{TimeError, TrustedClock, UNCERTAINTY_MS, check_against_witness};

// TI-RT2
#[test]
fn needs_two_sources_that_agree() {
    let mut c = TrustedClock::default();
    assert_eq!(c.read(&[1_000], 0), Err(TimeError::TooFewSources));
    assert_eq!(c.read(&[1_000, 1_251], 0), Err(TimeError::Disagree));
    assert_eq!(c.read(&[1_000, 1_250], 0), Ok(1_000));
    assert_eq!(c.read(&[3_000, 2_900, 2_950], 2_000), Ok(2_950));
}

// TI-RT2, U29: Δrecorded_at ≤ Δmonotonic + U
#[test]
fn bounds_advance_by_the_monotonic_clock() {
    let mut c = TrustedClock::default();
    c.read(&[10_000, 10_000], 500).unwrap();
    assert_eq!(c.read(&[11_251, 11_251], 1_500), Err(TimeError::Jump));
    assert_eq!(c.read(&[11_250, 11_250], 1_500), Ok(11_250));
    assert_eq!(c.read(&[11_300, 11_300], 1_000), Err(TimeError::Monotonic));
}

// TI-19: a reading may go back; the sequencer keeps recorded_at monotone
#[test]
fn a_backward_reading_is_returned_as_is() {
    let mut c = TrustedClock::default();
    c.read(&[10_000, 10_000], 0).unwrap();
    assert_eq!(c.read(&[9_900, 9_900], 10), Ok(9_900));
}

// a rejected reading does not move the reference point
#[test]
fn rejected_readings_leave_the_last_one() {
    let mut c = TrustedClock::default();
    c.read(&[10_000, 10_000], 0).unwrap();
    assert_eq!(c.read(&[10_000, 20_000], 100), Err(TimeError::Disagree));
    assert_eq!(c.read(&[10_300, 10_300], 100), Ok(10_300));
}

// TI-RT2, OP-140 m.5: the log clock may not run ahead of a witness by more than U
#[test]
fn witness_time_bounds_the_log_clock() {
    assert_eq!(check_against_witness(10_999, 10, 0), Ok(()));
    assert_eq!(
        check_against_witness(11_000, 10, 0),
        Err(TimeError::AheadOfWitness)
    );
    assert_eq!(check_against_witness(11_249, 10, UNCERTAINTY_MS), Ok(()));
    assert_eq!(
        check_against_witness(11_250, 10, UNCERTAINTY_MS),
        Err(TimeError::AheadOfWitness)
    );
    assert_eq!(check_against_witness(5, 100, UNCERTAINTY_MS), Ok(()));
}
