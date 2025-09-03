// SPDX-License-Identifier: BSD-2-Clause
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
pub use crate::arch_spec::arch::hexagon::HexagonRegister;
pub use keystone_engine::Keystone;
pub use log::trace;
pub use regex::Regex;
use styx_cpu_type::arch::backends::ArchRegister;
pub use styx_cpu_type::{arch::hexagon::HexagonVariants, Arch, ArchEndian, TargetExitReason};
use styx_errors::anyhow::Context;
pub use styx_pcode_translator::sla::hexagon_reg_to_str;
pub use styx_processor::{
    cpu::CpuBackend,
    event_controller::EventController,
    memory::{helpers::WriteExt, Mmu},
};

pub(crate) use crate::RegisterManager;
use crate::{
    memory::{sized_value::SizedValue, space_manager::HasSpaceManager},
    pcode_gen::{HasPcodeGenerator, RegisterTranslator},
    register_manager::{RegisterCallbackCpu, RegisterHandleError},
};
pub use styx_processor::cpu::CpuBackendExt;

use super::{backend::HexagonPcodeBackend, pkt_semantics::DEST_REG_OFFSET};

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

// this probably shouldn't ever be used other than in tests

pub fn read_dst_reg(
    backend: &mut HexagonPcodeBackend,
    reg: HexagonRegister,
) -> Result<SizedValue, RegisterHandleError> {
    let arch_reg: ArchRegister = reg.into();
    let (spc, gen) = backend.borrow_space_gen();

    let vnode = gen.get_register(&arch_reg).map(|i| {
        // Have to clone bc we modify
        let mut i = i.clone();
        i.offset += DEST_REG_OFFSET;
        i
    });

    match vnode {
        Some(ref varnode) => Ok(spc
            .read(varnode)
            .with_context(|| format!("error reading {reg:?} @ {vnode:?} from space"))?),
        None => Err(RegisterHandleError::CannotHandleRegister(arch_reg)),
    }
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
