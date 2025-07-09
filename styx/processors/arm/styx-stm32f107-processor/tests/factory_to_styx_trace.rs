// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//! Integration test: Emulation for `STM32F107` GPIO blink_flash

mod behavior_harnesses;

use behavior_harnesses::blink_flash_tester::run_blink_flash;
use std::time::Duration;
use styx_core::core::ExceptionBehavior;
use styx_core::grpc::args::{AppDefault, Target, TracePluginArgs};
use styx_core::prelude::*;
use styx_core::tracebus::TraceEventType;
use styx_core::util::logging::init_logging;
use styx_integration_tests::{ProcessorIntegrationTest, TestBins};
use styx_plugins::styx_trace::StyxTracePlugin;
use styx_stm32f107_processor::Stm32f107Builder;
use tap::Conv;

/// expect at least this many events
const MIN_EVENTS: usize = 1;
/// expect no more than this main events
const MAX_EVENTS: usize = 1;
/// How long to run the test before stoping the `Processor`
const TEST_DURATION: Duration = Duration::from_millis(1000);
/// The test event type (mask) we are looking for
const EVENT_MASK: TraceEventType = TraceEventType::STM32;

/// test blink_flash with `EmulationArgs`. All the assertions are
/// performed in [run_blink_flash](fn@common::run_blink_flash)
#[test]
#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
fn test_blink_flash() {
    init_logging();
    let exp_rng = (MIN_EVENTS, MAX_EVENTS);
    let proc = ProcessorBuilder::default()
        .with_builder(Stm32f107Builder {
            exception_behavior: ExceptionBehavior::Panic,
        })
        .with_backend(Backend::Unicorn)
        .with_target_program(TestBins::gpio_blink_bin())
        .add_plugin(TracePluginArgs::app_default().conv::<StyxTracePlugin>())
        .build()
        .unwrap();
    let blink =
        ProcessorIntegrationTest::from_proc(proc, Target::Stm32f107, TEST_DURATION, EVENT_MASK);

    run_blink_flash(blink, exp_rng);
}
