// SPDX-License-Identifier: BSD-2-Clause

//! Example: detecting loops with [`LoopDetectionPlugin`].
//!
//! Emulates an STM32F107 (ARM Cortex-M3) running a small GPIO "blink" firmware
//! and uses the loop-detection plugin to report a loop once it has iterated at
//! least a configured number of times.
//!
//! This binary and architecture is the same one used in the `diy-processor` plugin,
//! so look at that example to better understand this one.
//!
//! Note: the shadow stack plugin that the loop detection relies on depends on
//! control-flow classification, which is provided by the pcode backend, and
//! not on the Unicorn backend

use std::env;
use styx_emulator::core::util::logging::init_logging;
use styx_emulator::prelude::debug_tools::{LoopCallback, LoopDetectionPlugin, LoopReport};
use styx_emulator::prelude::*;
use styx_emulator::processors::arm::stm32f107::Stm32f107Builder;
use tracing::info;

const FW_PATH: &str = "../../data/test-binaries/arm/stm32f107/bin/blink_flash/blink_flash.bin";

fn get_firmware_path() -> String {
    env::var("FIRMWARE_PATH").unwrap_or_else(|_| FW_PATH.to_string())
}

fn set_env_log_info() {
    unsafe {
        if env::var("RUST_LOG").is_err() {
            env::set_var("RUST_LOG", "info");
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    set_env_log_info();
    init_logging();

    let on_loop: LoopCallback = Box::new(|report: &LoopReport| {
        println!(
            ">> loop detected: header={:#x}, function={:#x}, iterations={}, call depth={}",
            report.head_addr, report.frame_addr, report.iters, report.stack_depth,
        );
    });

    let loop_detector = LoopDetectionPlugin::new(
        5,             // threshold: report a loop once it iterates >= 5 times
        false,         // halt_on_detection: stop emulation at the first reported loop
        Some(on_loop), // on_detection callback (pass `None` to just use the built-in log)
        None,          // shadow_stack: `None` => the plugin manages its own private one
    );

    let mut proc = ProcessorBuilder::default()
        .with_builder(Stm32f107Builder)
        .with_target_program(get_firmware_path())
        // loop detection needs the pcode backend's control-flow classification.
        .with_backend(Backend::Pcode)
        .add_plugin(loop_detector)
        .build()?;

    info!("running until the first loop is detected...");
    // `blink_flash` loops forever, but `halt_on_detection` stops emulation at the
    // first reported loop, so `run(Forever)` returns.
    proc.run(Forever)?;
    info!("emulation stopped after detecting a loop");

    Ok(())
}
