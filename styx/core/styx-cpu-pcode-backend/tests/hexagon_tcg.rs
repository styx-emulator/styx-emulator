// SPDX-License-Identifier: BSD-2-Clause
//! Testing of Hexagon architecture using the pcode backend.
//!
//! Tests are taken from QEMU tcg test suite.
//!
//! To run:
//!
//! `cargo nextest run -p styx-cpu-pcode-backend -E "test(test_binutils_unittests::)" --failure-output never --run-ignored all --retries 0 --features hexagon-binutils-tests`
//!
#![cfg(feature = "hexagon-binutils-tests")]
#![cfg(not(feature = "disable-hexagon-tests"))] // hack for when using `--all-features`

use styx_cpu_pcode_backend::PcodeBackend;
use styx_cpu_type::{
    arch::blackfin::{BlackfinRegister, BlackfinVariants},
    Arch, ArchEndian, TargetExitReason,
};
use styx_hexagon_testdata::{binutils_tests, TestData};
use styx_loader::{Loader, MemoryLoaderDesc};
use styx_processor::{
    cpu::{CpuBackend, CpuBackendExt},
    event_controller::EventController,
    hooks::{CoreHandle, Hookable, Resolution, StyxHook},
    memory::{helpers::WriteExt, memory_region::MemoryRegion, MemoryPermissions, Mmu},
};
use test_case::test_case;

// List all tests and remove their extension (to paste into here).
// find bin/ | xargs --replace basename {}

// Don't run these tests unless explicitly asked to (they don't pass)
#[ignore]
#[test_case(binutils_tests::TEST_ATOMICS)]
#[test_case(binutils_tests::TEST_BREV)]
#[test_case(binutils_tests::TEST_CIRC)]
#[test_case(binutils_tests::TEST_DUAL_STORES)]
#[test_case(binutils_tests::TEST_FIRST)]
#[test_case(binutils_tests::TEST_FPSTUFF)]
#[test_case(binutils_tests::TEST_HEX_SIGSEGV)]
#[test_case(binutils_tests::TEST_HVX_HISTOGRAM)]
#[test_case(binutils_tests::TEST_HVX_MISC)]
#[test_case(binutils_tests::TEST_INVALID_SLOTS)]
#[test_case(binutils_tests::TEST_LOAD_ALIGN)]
#[test_case(binutils_tests::TEST_LOAD_UNPACK)]
#[test_case(binutils_tests::TEST_MEM_NOSHUF)]
#[test_case(binutils_tests::TEST_MEM_NOSHUF_EXCEPTION)]
#[test_case(binutils_tests::TEST_MISC)]
#[test_case(binutils_tests::TEST_MULTI_RESULT)]
#[test_case(binutils_tests::TEST_OVERFLOW)]
#[test_case(binutils_tests::TEST_PREG_ALIAS)]
#[test_case(binutils_tests::TEST_READ_WRITE_OVERLAP)]
#[test_case(binutils_tests::TEST_REG_MUT)]
#[test_case(binutils_tests::TEST_SCATTER_GATHER)]
#[test_case(binutils_tests::TEST_SIGNAL_CONTEXT)]
#[test_case(binutils_tests::TEST_TEST_ABS)]
#[test_case(binutils_tests::TEST_TEST_BITCNT)]
#[test_case(binutils_tests::TEST_TEST_BITSPLIT)]
#[test_case(binutils_tests::TEST_TEST_CALL)]
#[test_case(binutils_tests::TEST_TEST_CLOBBER)]
#[test_case(binutils_tests::TEST_TEST_CMP)]
#[test_case(binutils_tests::TEST_TEST_DOTNEW)]
#[test_case(binutils_tests::TEST_TEST_EXT)]
#[test_case(binutils_tests::TEST_TEST_FIBONACCI)]
#[test_case(binutils_tests::TEST_TEST_HL)]
#[test_case(binutils_tests::TEST_TEST_HWLOOPS)]
#[test_case(binutils_tests::TEST_TEST_JMP)]
#[test_case(binutils_tests::TEST_TEST_LSR)]
#[test_case(binutils_tests::TEST_TEST_MPYI)]
#[test_case(binutils_tests::TEST_TEST_PACKET)]
#[test_case(binutils_tests::TEST_TEST_REORDER)]
#[test_case(binutils_tests::TEST_TEST_ROUND)]
#[test_case(binutils_tests::TEST_TEST_VAVGW)]
#[test_case(binutils_tests::TEST_TEST_VCMPB)]
#[test_case(binutils_tests::TEST_TEST_VCMPW)]
#[test_case(binutils_tests::TEST_TEST_VLSRW)]
#[test_case(binutils_tests::TEST_TEST_VMAXH)]
#[test_case(binutils_tests::TEST_TEST_VMINH)]
#[test_case(binutils_tests::TEST_TEST_VPMPYH)]
#[test_case(binutils_tests::TEST_TEST_VSPLICEB)]
#[test_case(binutils_tests::TEST_UNALIGNED_PC)]
#[test_case(binutils_tests::TEST_USR)]
#[test_case(binutils_tests::TEST_V68_HVX)]
#[test_case(binutils_tests::TEST_V68_SCALAR)]
#[test_case(binutils_tests::TEST_V69_HVX)]
#[test_case(binutils_tests::TEST_V73_SCALAR)]
#[test_case(binutils_tests::TEST_VECTOR_ADD_INT)]
fn test_binutils_unittests(test: TestData) {
    styx_util::logging::init_logging();

    // TODO change to hexagon
    let mut backend = PcodeBackend::new_engine(
        Arch::Blackfin,
        BlackfinVariants::Bf512,
        ArchEndian::LittleEndian,
    );
    let mut mmu = Mmu::default_region_store();
    let mut ev = EventController::default();

    // Load elf into memory and initial registers
    load_elf(&mut backend, &mut mmu, test.bytes());

    // Stop on interrupt
    let interrupt_stop_hook = |mut backend: CoreHandle, _irqn| {
        backend.stop();
        Ok(())
    };
    backend
        .add_hook(StyxHook::interrupt(interrupt_stop_hook))
        .unwrap();

    // TODO change to hexagon register
    // write non-zero value to r0 to avoid false pass
    backend
        .write_register(BlackfinRegister::R0, 0x1337u32)
        .unwrap();

    let exit_reason = backend.execute(&mut mmu, &mut ev, 0x10000).unwrap();
    assert_eq!(
        exit_reason.exit_reason,
        TargetExitReason::HostStopRequest,
        "Machine did not stop properly."
    );

    // TODO change to hexagon register
    assert_eq!(
        backend.read_register::<u32>(BlackfinRegister::R0).unwrap(),
        0,
        "Test failed! Did not call pass."
    )
}

fn load_description(
    backend: &mut PcodeBackend,
    mmu: &mut Mmu,
    mut program_load_description: MemoryLoaderDesc,
) {
    for (reg, value) in program_load_description.take_registers().into_iter() {
        println!("setting {reg:?} to 0x{value:X}");
        backend.write_register(reg, value as u32).unwrap();
    }

    for mut region in program_load_description.take_memory_regions().into_iter() {
        unsafe {
            // add more bytes to region so there are no accidental unmapped memory operations
            region.align_size(0x1000, 0).unwrap();
        }
        mmu.add_memory_region(
            MemoryRegion::new(region.base(), region.size(), MemoryPermissions::all()).unwrap(),
        )
        .unwrap();
        // copy over data
        mmu.data()
            .write(region.base())
            .bytes(&region.read_data(region.base(), region.size()).unwrap())
            .unwrap();
    }
}
/// Loads program memory regions and initial registers (e.g. entry address)
fn load_elf(backend: &mut PcodeBackend, mmu: &mut Mmu, program: &[u8]) {
    let program_load_description = styx_loader::ElfLoader::default()
        .load_bytes(program.to_owned().into(), Default::default())
        .unwrap();

    load_description(backend, mmu, program_load_description)
}
