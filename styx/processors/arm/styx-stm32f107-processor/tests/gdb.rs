// SPDX-License-Identifier: BSD-2-Clause
//! end to end tests for stm32f107
use styx_core::cpu::arch::arm::gdb_targets::ArmMProfileDescription;
use styx_core::prelude::*;
use styx_core::util::{logging::init_logging, resolve_test_bin};
use styx_integration_tests::gdb_core_test_suite;

const BLINK_FLASH_PATH: &str = "arm/stm32f107/bin/blink_flash/blink_flash.bin";

/// use this method to create your initial test processorbuilder
fn build_stm32f107(target_program_path: &'static str) -> ProcessorBuilder<'static> {
    init_logging();
    let test_bin_path = resolve_test_bin(target_program_path);

    // create default processor with gdb plugin
    ProcessorBuilder::default()
        .with_loader(RawLoader)
        .with_target_program(test_bin_path)
        .with_ipc_port(IPCPort::any())
        .with_builder(styx_stm32f107_processor::Stm32f107Builder)
}

/// pre-packaged builder for blink-flash
fn stm32f107_blink_flash() -> ProcessorBuilder<'static> {
    build_stm32f107(BLINK_FLASH_PATH)
}

// runs gdb core test suite
gdb_core_test_suite!(
    "pc",
    BLINK_FLASH_PATH,
    0x59d4,                 // start address of bin
    0x59d6,                 // breakpoint one
    0x5906,                 // breakpoint two
    0x40011014,             // watchpoint 1
    ArmMProfileDescription, // type of gdb target description
    stm32f107_blink_flash,
);
