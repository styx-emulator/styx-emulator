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
pub use keystone_engine::Keystone;
pub use log::trace;
pub use regex::Regex;
pub use styx_cpu_type::{
    arch::hexagon::{HexagonRegister, HexagonVariants},
    Arch, ArchEndian, TargetExitReason,
};
pub use styx_pcode_translator::sla::hexagon_reg_to_str;
pub use styx_processor::{
    event_controller::EventController,
    memory::{helpers::WriteExt, Mmu},
};

pub(crate) use crate::PcodeBackend;
pub(crate) use crate::RegisterManager;
pub use styx_processor::cpu::{CpuBackend, CpuBackendExt};

mod branching;
mod compound;
mod dotnew;
mod duplex;
mod general;
mod hwloop;
mod immediate;
mod packet;
mod reg_postfix;
mod regpair;

pub fn setup_asm(
    asm_str: &str,
    expected_asm: Option<Vec<u8>>,
) -> (PcodeBackend, Mmu, EventController) {
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
    trace!("bytes {:x?} asm {}", code, asm_str);

    // takes the objdump and extracts the binary from it
    //  duplex instruction:
    setup_cpu(init_pc, code)
}

pub fn setup_cpu(init_pc: u64, code: Vec<u8>) -> (PcodeBackend, Mmu, EventController) {
    let mut cpu = PcodeBackend::new_engine(
        Arch::Hexagon,
        HexagonVariants::QDSP6V66,
        ArchEndian::BigEndian,
    );

    cpu.set_pc(init_pc).unwrap();

    let mut mmu = Mmu::default();
    let ev = EventController::default();
    mmu.code().write(init_pc).bytes(&code).unwrap();

    (cpu, mmu, ev)
}

pub fn setup_objdump(objdump: &str) -> (PcodeBackend, Mmu, EventController) {
    styx_util::logging::init_logging();

    const START: u64 = 0x1000u64;

    setup_cpu(
        START,
        styx_util::parse_objdump(objdump).expect("failed to parse objdump supplied to test case!"),
    )
}

pub fn get_isa_pc(cpu: &mut PcodeBackend) -> u32 {
    RegisterManager::read_register(cpu, HexagonRegister::Pc.into())
        .unwrap()
        .to_u64()
        .unwrap() as u32
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
