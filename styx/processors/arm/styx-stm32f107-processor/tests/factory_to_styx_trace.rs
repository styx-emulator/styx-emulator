// SPDX-License-Identifier: BSD-2-Clause
//! Integration test: Emulation for `STM32F107` GPIO blink_flash
#![cfg(feature = "unicorn-backend")]
mod behavior_harnesses;

use behavior_harnesses::blink_flash_tester::run_blink_flash;
use std::time::Duration;
use styx_core::grpc::args::{AppDefault, Target, TracePluginArgs};
use styx_core::prelude::*;
use styx_core::tracebus::TraceEventType;
use styx_core::util::logging::init_logging;
use styx_integration_tests::{ProcessorIntegrationTest, TestBins};
use styx_plugins::styx_trace::StyxTracePlugin;
use styx_stm32f107_processor::Stm32f107Builder;
use tap::Conv;

/// expect at least this many events
const MIN_EVENTS: usize = 1000;
/// expect no more than this main events
const MAX_EVENTS: usize = usize::MAX;
/// How long to run the test before stoping the `Processor`
const TEST_DURATION: Duration = Duration::from_millis(1000);
/// The test event type (mask) we are looking for
const EVENT_MASK: TraceEventType = TraceEventType::MEM_WRT;

/// test blink_flash with `EmulationArgs`. All the assertions are
/// performed in [run_blink_flash](fn@common::run_blink_flash)
#[test]
#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
fn test_blink_flash() {
    init_logging();
    let exp_rng = (MIN_EVENTS, MAX_EVENTS);
    let proc = ProcessorBuilder::default()
        .with_builder(Stm32f107Builder)
        .with_backend(Backend::Unicorn)
        .with_target_program(TestBins::gpio_blink_bin())
        .add_plugin(TracePluginArgs::app_default().conv::<StyxTracePlugin>())
        .build()
        .unwrap();
    let blink =
        ProcessorIntegrationTest::from_proc(proc, Target::Stm32f107, TEST_DURATION, EVENT_MASK);

    run_blink_flash(blink, exp_rng);
}
