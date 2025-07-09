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
use styx_core::cpu::arch::arm::gdb_targets::Armv7emDescription;
use styx_core::loader::RawLoader;
use styx_core::prelude::*;
use styx_core::processor::ProcessorBuilder;
use styx_integration_tests::gdb_core_test_suite;
use styx_kinetis21_processor::Kinetis21Builder;

const BLINK_FLASH_PATH: &str = "arm/kinetis_21/bin/led_output/led_output_debug.bin";

fn kinetis_21_gdb_blink_flash() -> ProcessorBuilder<'static> {
    ProcessorBuilder::default()
        .with_backend(Backend::Unicorn)
        .with_target_program(resolve_test_bin(BLINK_FLASH_PATH))
        .with_loader(RawLoader)
        .with_builder(Kinetis21Builder::default())
}

gdb_core_test_suite!(
    "pc",
    BLINK_FLASH_PATH,
    0x48c,
    0x756,
    0x780,
    0x1fff0050,
    Armv7emDescription,
    kinetis_21_gdb_blink_flash,
);
