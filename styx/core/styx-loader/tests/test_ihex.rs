// SPDX-License-Identifier: BSD-2-Clause
//! Integration tests for the Intel HEX loader

use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;

use styx_loader::{IhexLoader, Loader};
use styx_util::resolve_test_bin;

#[test]
fn test_load_betaflight_hex() {
    // Try to load the Betaflight test file using the test_bin_path utility
    let hex_path = resolve_test_bin("arm/stm32f405/bin/betaflight_4.5.0_STM32F405.hex");

    let hex_content = fs::read(&hex_path).expect("Failed to read Betaflight HEX file");

    let loader = IhexLoader;
    let mut desc = loader
        .load_bytes(Cow::Borrowed(&hex_content), HashMap::new())
        .expect("Failed to load Betaflight HEX file");

    // Verify that regions were loaded
    let regions = desc.take_memory_regions();
    assert!(
        !regions.is_empty(),
        "No memory regions loaded from Betaflight HEX"
    );

    // The STM32F405 flash typically starts at 0x08000000
    let has_flash_region = regions.iter().any(|r| r.base() >= 0x08000000);
    assert!(
        has_flash_region,
        "No flash region found at expected address (0x08000000+)"
    );

    // Check that we have substantial data (Betaflight firmware is typically > 100KB)
    let total_size: u64 = regions.iter().map(|r| r.size()).sum();
    assert!(
        total_size > 100_000,
        "Total loaded size ({total_size} bytes) seems too small for firmware"
    );
}

#[test]
fn test_load_betaflight_hex_with_arch_hint() {
    use styx_cpu_type::Arch;

    // Try to load the Betaflight test file with architecture hint using the test_bin_path utility
    let hex_path = resolve_test_bin("arm/stm32f405/bin/betaflight_4.5.0_STM32F405.hex");

    let hex_content = fs::read(&hex_path).expect("Failed to read Betaflight HEX file");

    let loader = IhexLoader;
    let mut hints = HashMap::new();
    hints.insert(
        Box::from("arch"),
        Box::new(Arch::Arm) as Box<dyn std::any::Any>,
    );

    let mut desc = loader
        .load_bytes(Cow::Borrowed(&hex_content), hints)
        .expect("Failed to load Betaflight HEX file with arch hint");

    // If there's a start address in the file, it should have been set as PC
    let registers = desc.take_registers();

    // The file has a Start Linear Address record (type 05) which should set the PC
    assert!(
        !registers.is_empty(),
        "No registers loaded from Betaflight HEX with arch hint"
    );

    // Check that the PC is set to the expected start address
    // should have start pc at 0x08000000
    let mut has_pc = false;
    for (reg, value) in &registers {
        // The start address should be the flash region (0x08000000)
        if format!("{reg:?}").to_lowercase().contains("pc") {
            has_pc = true;
            assert!(
                *value == 0x08000000,
                "PC start address 0x{value:08X} is not at expected flash base (0x08000000)"
            );
        }
    }

    assert!(has_pc, "Intel HEX loader did not set the PC register");
}
