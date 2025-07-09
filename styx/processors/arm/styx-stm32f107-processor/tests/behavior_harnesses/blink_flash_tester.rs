// SPDX-License-Identifier: BSD-2-Clause
//! Helper functions for integrations tests
use styx_core::tracebus::{strace_teardown, TraceProvider, Traceable};
use styx_integration_tests::{path_exists, run_test, ProcessorIntegrationTest};
use tracing::debug;

/// Run the blink_flash target for a second, make assertions about
/// the number of events that get emitted
/// - at least `exp_rng.0`
/// - no more than `exp_rng.1`
/// - all events shoud be of type `blink.event_mask`
pub fn run_blink_flash(mut blink: ProcessorIntegrationTest, exp_rng: (usize, usize)) {
    // Run the meat of the test ...
    let trace_path = blink.trace_path();
    let run_duration = blink.timeout;
    let event_mask = blink.event_mask;

    assert!(!path_exists(&trace_path), "trace file does not exist");

    let events = run_test(&mut blink);
    assert!(path_exists(&trace_path), "trace file exist");
    strace_teardown!();

    // Tracefile is cleaned up
    assert!(!path_exists(&trace_path), "trace file does not exist");
    // count target specific events
    let evcount = events
        .iter()
        .filter(|&e| e.event_type() == event_mask)
        .count();
    // We have about the right number of events
    let fail_msg = format!("Events: expected: {:?}, got: {}", exp_rng, events.len());

    assert_eq!(events.len(), evcount);
    if events.len() < exp_rng.0 {
        panic!("not enough events: {}", &fail_msg);
    }
    if events.len() > exp_rng.1 {
        panic!("too many events: {}", &fail_msg);
    }
    debug!(
        "Test complete: captured {} events in {:?}",
        events.len(),
        run_duration,
    );
}
