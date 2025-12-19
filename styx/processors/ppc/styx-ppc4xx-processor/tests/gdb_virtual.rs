// SPDX-License-Identifier: BSD-2-Clause
//! This tests that the GDB implementation uses virtual addressing for breakpoints, memory operations, and watchpoints.
//!
//! The powerpc target is loaded with a dummy TLB implementation (see `fn translation()`) that places
//! vaddr 0x0 at paddr `VIRTUAL_OFFSET` and translates virtual address at 0xF0000000 and above to 0xA0000000.
//! The firmware is loaded at paddr `VIRTUAL_OFFSET` and the gdb tests are run with the vaddrs given.

use styx_core::arch::ppc32::Ppc32Variants;
use styx_core::core::builder::BuildProcessorImplArgs;
use styx_core::cpu::arch::ppc32::gdb_targets::Ppc4xxTargetDescription;
use styx_core::cpu::PcodeBackend;
use styx_core::event_controller::DummyEventController;
use styx_core::memory::{FnTlb, TlbProcessor, TlbTranslateResult};
use styx_core::{prelude::*, util};

use styx_core::util::resolve_test_bin;
use styx_integration_tests::gdb_core_test_suite;

const FREERTOS_PATH: &str = "ppc/ppc405/bin/freertos.bin";

/// Virtual address 0 start here in physical.
const VIRTUAL_OFFSET: u64 = 0xC000_0000;

/// Build a ppc405 processor that can *limp* through a freertos binary and has some virtual addressing.
///
/// The FreeRTOS image will be loaded at Physical address 0xC0000000.
///
/// This initialization code is taken from the ppc405 processor builder with the peripherals removed.
/// We don't need accurate emulation for the GDB tests.
fn virtual_gdb_tests_builder() -> ProcessorBuilder<'static> {
    util::logging::init_logging();
    let test_bin_path = resolve_test_bin(FREERTOS_PATH);
    let loader_yaml = format!(
        r#"
        - !FileRaw
            # gdb_core_test_suite requires that the file be loaded at paddr VIRTUAL_OFFSET and vaddr 0x0.
            base: 0x{VIRTUAL_OFFSET:X}
            file: {test_bin_path}
            perms: !AllowAll
        - !RegisterImmediate
            # address of _start
            register: pc
            value: 0x20c4
"#
    );

    let custom_builder = |args: &BuildProcessorImplArgs| {
        let cpu = if let Backend::Pcode = args.backend {
            Box::new(PcodeBackend::new_engine_config(
                Ppc32Variants::Ppc405,
                ArchEndian::BigEndian,
                &args.into(),
            ))
        } else {
            return Err(BackendNotSupported(args.backend))
                .context("ppc405 processor only supports pcode backend");
        };

        fn translation(
            addr: u64,
            _op: MemoryOperation,
            _mtype: MemoryType,
            _tlb: &mut TlbProcessor,
        ) -> TlbTranslateResult {
            if addr > 0xF0000000 {
                Ok(addr - (0x50000000))
            } else {
                Ok(addr + VIRTUAL_OFFSET)
            }
        }

        let tlb = Box::new(FnTlb::new(translation));
        let mut memory = MemoryBackend::new_region_store();
        memory.memory_map(0, 2u64.pow(32), MemoryPermissions::all())?;

        let cec = Box::new(DummyEventController::default());

        let peripherals: Vec<Box<dyn Peripheral>> = Vec::new();

        let mut hints = LoaderHints::new();
        hints.insert("arch".to_string().into_boxed_str(), Box::new(Arch::Ppc32));
        Ok(ProcessorBundle {
            cpu,
            memory,
            tlb,
            event_controller: cec,
            peripherals,
            loader_hints: hints,
        })
    };

    ProcessorBuilder::default()
        .with_builder(custom_builder)
        .with_ipc_port(IPCPort::any())
        .with_loader(ParameterizedLoader::default())
        .with_input_bytes(loader_yaml.as_bytes().to_owned().into())
}

// see documentation of the test suite for all requirements of
// test environment (there are many :D)
gdb_core_test_suite!(
    "pc",
    FREERTOS_PATH,
    0x20c4,
    0x20d0,
    0x20dc,
    0xFFFFFF54,
    Ppc4xxTargetDescription,
    Ppc32Variants::Ppc405,
    virtual_gdb_tests_builder,
);
