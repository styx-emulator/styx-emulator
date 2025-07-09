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
//! end to end tests for stm32f107
use styx_core::core::ExceptionBehavior;
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
        .with_builder(styx_stm32f107_processor::Stm32f107Builder {
            exception_behavior: ExceptionBehavior::Panic,
        })
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
