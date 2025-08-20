// SPDX-License-Identifier: BSD-2-Clause
#![cfg(feature = "unicorn-backend")]
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
