// SPDX-License-Identifier: BSD-2-Clause
//! Integration test comparing Intel HEX and ELF loader outputs
//!
//! This test ensures that the Intel HEX loader and ELF loader produce
//! consistent memory mappings when loading the same binary in different formats.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use styx_loader::{ElfLoader, IhexLoader, Loader};
use styx_memory::MemoryBank;

/// Helper function to get the path to test data
///
/// **NOTE**: This test data is specific to exercising loader functionality
/// and points to a sub-folder of the `styx-loader` crate.
fn test_data_path(filename: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("test-data");
    path.push("hello-world");
    path.push(filename);
    path
}

#[test]
fn test_elf_ihex_memory_consistency() {
    // Load the ELF file
    let elf_path = test_data_path("hello.elf");
    let elf_content = fs::read(&elf_path).expect("Failed to read hello.elf");

    let elf_loader = ElfLoader::default();
    let mut elf_desc = elf_loader
        .load_bytes(Cow::Borrowed(&elf_content), HashMap::new())
        .expect("Failed to load ELF file");

    // Load the Intel HEX file
    let hex_path = test_data_path("hello.hex");
    let hex_content = fs::read(&hex_path).expect("Failed to read hello.hex");

    let ihex_loader = IhexLoader;
    let mut ihex_desc = ihex_loader
        .load_bytes(Cow::Borrowed(&hex_content), HashMap::new())
        .expect("Failed to load Intel HEX file");

    // Extract memory regions from both loaders
    let elf_regions = elf_desc.take_memory_regions();
    let ihex_regions = ihex_desc.take_memory_regions();

    // Both loaders should load some regions
    assert!(
        !elf_regions.is_empty(),
        "ELF loader produced no memory regions"
    );
    assert!(
        !ihex_regions.is_empty(),
        "Intel HEX loader produced no memory regions"
    );

    // Keeping this here to keep someone else from wasting 8 hours:
    //
    // The gnu toolchain likes to change the number of
    // emitted segments / sections etc. based on size or region, overall size
    // of segment, and sizes of sections for both the ELF and Intel HEX.
    //
    // The loaders should have the same number of regions
    // assert_eq!(
    //     elf_regions.len(),
    //     ihex_regions.len(),
    //     "ELF and Intel HEX loaders produced different number of memory regions"
    // );

    // The data contained in the ihex should also be contained in the ELF:

    // for each region in the ihex, ensure that the data, size, etc exists in the
    // regions returned by the elf loader
    for ihex_region in &ihex_regions {
        let ihex_range = ihex_region.get_range();

        // is the region in any of the ELF regions?
        let mut found = false;
        let mut data_correct = false;
        for elf_region in &elf_regions {
            // if the elf region contains the proper ihex range
            // we need to assert the data is correct
            if elf_region.contains_range(&ihex_range) {
                // we found the regions
                found = true;

                // now check data correctness
                let elf_data = elf_region
                    .read_data(ihex_range.base(), ihex_range.size())
                    .expect("failed to read data from elf contents");

                let ihex_data = ihex_region
                    .read_data(ihex_region.base(), ihex_region.size())
                    .expect("failed to read data from ihex contents");

                assert_eq!(elf_data, ihex_data, "ELF data does not match IHEX data");
                data_correct = true;
                break;
            }
        }

        assert!(found, "did not find IHEX region: {ihex_region:?} in ELF");
        assert!(
            data_correct,
            "IHEX region: {ihex_region:?} data was not correct in ELF"
        );
    }
}

#[test]
fn test_elf_ihex_range_consistency() {
    // Load both files
    let elf_path = test_data_path("hello.elf");
    let elf_content = fs::read(&elf_path).expect("Failed to read hello.elf");

    let hex_path = test_data_path("hello.hex");
    let hex_content = fs::read(&hex_path).expect("Failed to read hello.hex");

    let elf_loader = ElfLoader::default();
    let mut elf_desc = elf_loader
        .load_bytes(Cow::Borrowed(&elf_content), HashMap::new())
        .expect("Failed to load ELF file");

    let ihex_loader = IhexLoader;
    let mut ihex_desc = ihex_loader
        .load_bytes(Cow::Borrowed(&hex_content), HashMap::new())
        .expect("Failed to load Intel HEX file");

    // Calculate total sizes
    let elf_regions = elf_desc.take_memory_regions();
    let ihex_regions = ihex_desc.take_memory_regions();

    let elf_bank = MemoryBank::from_regions_iter(elf_regions).unwrap();
    let ihex_bank = MemoryBank::from_regions_iter(ihex_regions).unwrap();

    let elf_range = elf_bank.get_range().unwrap();
    let ihex_range = ihex_bank.get_range().unwrap();

    assert_eq!(elf_range, ihex_range, "ELF range differs from IHEX range");
}

#[test]
fn test_ihex_start_address_extraction() {
    use styx_cpu_type::Arch;

    // Load the Intel HEX file with architecture hint
    let hex_path = test_data_path("hello.hex");
    let hex_content = fs::read(&hex_path).expect("Failed to read hello.hex");

    let ihex_loader = IhexLoader;
    let mut hints = HashMap::new();
    hints.insert(
        Box::from("arch"),
        Box::new(Arch::Arm) as Box<dyn std::any::Any>,
    );

    let mut ihex_desc = ihex_loader
        .load_bytes(Cow::Borrowed(&hex_content), hints)
        .expect("Failed to load Intel HEX file");

    // Check if a start address was set
    let registers = ihex_desc.take_registers();

    // should have start pc at 0x08000000
    assert!(
        !registers.is_empty(),
        "Intel HEX loader did not set any registers - expected PC"
    );

    let mut has_pc = false;
    for (reg, value) in &registers {
        // The start address should be the flash region (0x08000001)
        // by default its 0x80000000, and a +1 for thumb mode
        if format!("{reg:?}").to_lowercase().contains("pc") {
            has_pc = true;
            assert!(
                *value == 0x08000001,
                "PC start address 0x{value:08X} is not at expected flash base (0x08000001)"
            );
        }
    }

    assert!(has_pc, "Intel HEX loader did not set the PC register");
}

#[test]
fn test_ihex_elf_entry_point_consistency() {
    use styx_cpu_type::Arch;

    // Load ELF with architecture hint
    let elf_path = test_data_path("hello.elf");
    let elf_content = fs::read(&elf_path).expect("Failed to read hello.elf");

    let elf_loader = ElfLoader::default();
    let mut elf_hints = HashMap::new();
    elf_hints.insert(
        Box::from("arch"),
        Box::new(Arch::Arm) as Box<dyn std::any::Any>,
    );

    let mut elf_desc = elf_loader
        .load_bytes(Cow::Borrowed(&elf_content), elf_hints)
        .expect("Failed to load ELF file");

    // Load Intel HEX with architecture hint
    let hex_path = test_data_path("hello.hex");
    let hex_content = fs::read(&hex_path).expect("Failed to read hello.hex");

    let ihex_loader = IhexLoader;
    let mut ihex_hints = HashMap::new();
    ihex_hints.insert(
        Box::from("arch"),
        Box::new(Arch::Arm) as Box<dyn std::any::Any>,
    );

    let mut ihex_desc = ihex_loader
        .load_bytes(Cow::Borrowed(&hex_content), ihex_hints)
        .expect("Failed to load Intel HEX file");

    // Get entry points from both
    let elf_registers = elf_desc.take_registers();
    let ihex_registers = ihex_desc.take_registers();

    // They should both be setting registers
    assert!(
        !elf_registers.is_empty(),
        "ELF loader did not set any registers"
    );
    assert!(
        !ihex_registers.is_empty(),
        "Intel HEX loader did not set any registers"
    );

    // Both should have a PC register set

    let elf_pc = elf_registers
        .iter()
        .find(|(reg, _)| format!("{reg:?}").contains("Pc"));
    let ihex_pc = ihex_registers
        .iter()
        .find(|(reg, _)| format!("{reg:?}").contains("Pc"));
    assert!(elf_pc.is_some(), "ELF loader did not set the PC register");
    assert!(
        ihex_pc.is_some(),
        "Intel HEX loader did not set the PC register"
    );

    let elf_pc = elf_pc.unwrap().1;
    let ihex_pc = ihex_pc.unwrap().1;

    // The entrypoints should match
    assert_eq!(
        elf_pc, ihex_pc,
        "Entry point mismatch: ELF PC = 0x{elf_pc:08X}, Intel HEX PC = 0x{ihex_pc:08X}"
    );
}
