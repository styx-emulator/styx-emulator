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
//! `GDB` support macros and utilities for `mips32` targets
use super::Mips32Register;
use crate::arch::backends::{ArchRegister, BasicArchRegister};
use crate::arch::CpuRegister;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use styx_macros::gdb_target_description;
use styx_sync::lazy_static;
use styx_util::gdb_xml::MIPS_CPU;

lazy_static! {
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    pub static ref MIPS32_CPU_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, Mips32Register::R0.register()),
        (1, Mips32Register::R1.register()),
        (2, Mips32Register::R2.register()),
        (3, Mips32Register::R3.register()),
        (4, Mips32Register::R4.register()),
        (5, Mips32Register::R5.register()),
        (6, Mips32Register::R6.register()),
        (7, Mips32Register::R7.register()),
        (8, Mips32Register::R8.register()),
        (9, Mips32Register::R9.register()),
        (10, Mips32Register::R10.register()),
        (11, Mips32Register::R11.register()),
        (12, Mips32Register::R12.register()),
        (13, Mips32Register::R13.register()),
        (14, Mips32Register::R14.register()),
        (15, Mips32Register::R15.register()),
        (16, Mips32Register::R16.register()),
        (17, Mips32Register::R17.register()),
        (18, Mips32Register::R18.register()),
        (19, Mips32Register::R19.register()),
        (20, Mips32Register::R20.register()),
        (21, Mips32Register::R21.register()),
        (22, Mips32Register::R22.register()),
        (23, Mips32Register::R23.register()),
        (24, Mips32Register::R24.register()),
        (25, Mips32Register::R25.register()),
        (26, Mips32Register::R26.register()),
        (27, Mips32Register::R27.register()),
        (28, Mips32Register::R28.register()),
        (29, Mips32Register::R29.register()),
        (30, Mips32Register::R30.register()),
        (31, Mips32Register::R31.register()),
        (33, Mips32Register::Lo.register()),
        (34, Mips32Register::Hi.register()),
        (37, Mips32Register::Pc.register()),
    ]);
}

/// Mips32 Core Cpu
#[gdb_target_description]
#[derive(Debug, Default)]
pub struct Mips32CpuTargetDescription {
    #[args(
        gdb_arch_name("mips"),
        gdb_feature_xml(MIPS_CPU),
        register_map(MIPS32_CPU_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::Mips32(Mips32Register::Pc))),
        endianness(ArchEndian::BigEndian)
    )]
    args: PhantomData<()>,
}
