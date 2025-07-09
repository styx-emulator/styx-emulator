// SPDX-License-Identifier: BSD-2-Clause
#![cfg(feature = "arch_bfin")]

use arbitrary_int::u40;
use styx_cpu_pcode_backend::PcodeBackend;
use styx_cpu_type::{
    arch::blackfin::{BlackfinRegister, BlackfinVariants},
    Arch, ArchEndian,
};
use styx_processor::cpu::CpuBackendExt;

/// Test writing to A0/A1 and reading from ANx/ANw.
#[cfg_attr(miri, ignore)]
#[test]
fn test_accumulator_read_write() {
    let mut backend = PcodeBackend::new_engine(
        Arch::Blackfin,
        BlackfinVariants::Bf512,
        ArchEndian::LittleEndian,
    );

    backend
        .write_register(BlackfinRegister::A0, u40::new(0x6613371337u64))
        .unwrap();
    backend
        .write_register(BlackfinRegister::A1, u40::new(0x33DEADBEEFu64))
        .unwrap();

    assert_eq!(
        0x66u32,
        backend.read_register::<u32>(BlackfinRegister::A0x).unwrap()
    );
    assert_eq!(
        0x33u32,
        backend.read_register::<u32>(BlackfinRegister::A1x).unwrap()
    );

    assert_eq!(
        0x13371337u32,
        backend.read_register::<u32>(BlackfinRegister::A0w).unwrap()
    );
    assert_eq!(
        0xDEADBEEFu32,
        backend.read_register::<u32>(BlackfinRegister::A1w).unwrap()
    );
}
