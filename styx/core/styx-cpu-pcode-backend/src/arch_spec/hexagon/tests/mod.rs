// SPDX-License-Identifier: BSD-2-Clause
pub use crate::arch_spec::arch::hexagon::HexagonRegister;
pub use keystone_engine::Keystone;
pub use log::trace;
pub use regex::Regex;
pub use styx_cpu_type::{arch::hexagon::HexagonVariants, Arch, ArchEndian, TargetExitReason};
pub use styx_pcode_translator::sla::hexagon_reg_to_str;
pub use styx_processor::{
    cpu::CpuBackend,
    event_controller::EventController,
    memory::{helpers::WriteExt, Mmu},
};

pub(crate) use crate::RegisterManager;
pub use styx_processor::cpu::CpuBackendExt;

use super::backend::HexagonPcodeBackend;

mod banking;
mod branching;
mod compound;
mod dotnew;
mod dual_jumps;
mod duplex;
mod general;
mod hwloop;
mod immediate;
mod packet;
mod predicate_anding;
mod programs;
mod reg_postfix;
mod regpair;
mod sequencing;

pub fn setup_asm(
    asm_str: &str,
    expected_asm: Option<Vec<u8>>,
) -> (HexagonPcodeBackend, Mmu, EventController) {
    styx_util::logging::init_logging();
    // objdump from example ppc program
    // notably load/store operations are omitted because sleigh uses dynamic pointers
    //   to represent memory spaces which change run to run.
    let init_pc = 0x1000u64;

    // Assemble instructions
    // Processor default to thumb so we use that
    let ks = Keystone::new(
        keystone_engine::Arch::HEXAGON,
        keystone_engine::Mode::BIG_ENDIAN,
    )
    .expect("Could not initialize Keystone engine");
    let asm = ks
        .asm(asm_str.to_owned(), init_pc)
        .expect("Could not assemble");
    let code = asm.bytes;

    // Optional param
    if let Some(expected_asm) = expected_asm {
        assert_eq!(code, expected_asm);
    }
    trace!("bytes {code:x?} asm {asm_str}");

    // takes the objdump and extracts the binary from it
    //  duplex instruction:
    setup_cpu_pc(init_pc, code)
}

pub fn setup_cpu() -> (HexagonPcodeBackend, Mmu, EventController) {
    let cpu = HexagonPcodeBackend::new_engine(
        Arch::Hexagon,
        HexagonVariants::QDSP6V66,
        ArchEndian::BigEndian,
    );

    let mmu = Mmu::default();
    let ev = EventController::default();

    (cpu, mmu, ev)
}

pub fn setup_cpu_pc(init_pc: u64, code: Vec<u8>) -> (HexagonPcodeBackend, Mmu, EventController) {
    let (mut cpu, mut mmu, ev) = setup_cpu();
    cpu.set_pc(init_pc).unwrap();

    mmu.code().write(init_pc).bytes(&code).unwrap();
    trace!("wrote code to mmu");

    (cpu, mmu, ev)
}

pub fn setup_objdump(objdump: &str) -> (HexagonPcodeBackend, Mmu, EventController) {
    styx_util::logging::init_logging();

    const START: u64 = 0x1000u64;

    setup_cpu_pc(
        START,
        styx_util::parse_objdump(objdump).expect("failed to parse objdump supplied to test case!"),
    )
}

pub fn get_isa_pc(cpu: &mut HexagonPcodeBackend) -> u32 {
    let pc = RegisterManager::read_register(cpu, HexagonRegister::Pc.into())
        .unwrap()
        .to_u64()
        .unwrap() as u32;
    trace!("get_isa_pc returns {pc:x}");
    pc
}

// TODO:
// need to test load/stores (non dotnew) here
//
// also need something that tests the position of duplex instructions within a larger packet
// VERY heavily.
//
// need some tests related to register pairs
//
// also need some real programs, compiled with clang
// duplex imm test,
// hwloop test, jump test
// .new test, interrupt test??
// later: test function calls
