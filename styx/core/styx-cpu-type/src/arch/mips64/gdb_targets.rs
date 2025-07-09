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
//! `GDB` support macros and utilities for `mips64` targets
use super::Mips64Register;
use crate::arch::backends::{ArchRegister, BasicArchRegister};
use crate::arch::CpuRegister;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use styx_macros::gdb_target_description;
use styx_sync::lazy_static;
use styx_util::gdb_xml::MIPS64_CPU;

lazy_static! {
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    static ref MIPS64_CPU_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, Mips64Register::R0.register()),
        (1, Mips64Register::R1.register()),
        (2, Mips64Register::R2.register()),
        (3, Mips64Register::R3.register()),
        (4, Mips64Register::R4.register()),
        (5, Mips64Register::R5.register()),
        (6, Mips64Register::R6.register()),
        (7, Mips64Register::R7.register()),
        (8, Mips64Register::R8.register()),
        (9, Mips64Register::R9.register()),
        (10, Mips64Register::R10.register()),
        (11, Mips64Register::R11.register()),
        (12, Mips64Register::R12.register()),
        (13, Mips64Register::R13.register()),
        (14, Mips64Register::R14.register()),
        (15, Mips64Register::R15.register()),
        (16, Mips64Register::R16.register()),
        (17, Mips64Register::R17.register()),
        (18, Mips64Register::R18.register()),
        (19, Mips64Register::R19.register()),
        (20, Mips64Register::R20.register()),
        (21, Mips64Register::R21.register()),
        (22, Mips64Register::R22.register()),
        (23, Mips64Register::R23.register()),
        (24, Mips64Register::R24.register()),
        (25, Mips64Register::R25.register()),
        (26, Mips64Register::R26.register()),
        (27, Mips64Register::R27.register()),
        (28, Mips64Register::R28.register()),
        (29, Mips64Register::R29.register()),
        (30, Mips64Register::R30.register()),
        (31, Mips64Register::R31.register()),
        (33, Mips64Register::Lo.register()),
        (34, Mips64Register::Hi.register()),
        (37, Mips64Register::Pc.register()),
    ]);

    static ref MIPS64_FPU_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from_iter([
        (0, Mips64Register::R0.register()),
        (1, Mips64Register::R1.register()),
        (2, Mips64Register::R2.register()),
        (3, Mips64Register::R3.register()),
        (4, Mips64Register::R4.register()),
        (5, Mips64Register::R5.register()),
        (6, Mips64Register::R6.register()),
        (7, Mips64Register::R7.register()),
        (8, Mips64Register::R8.register()),
        (9, Mips64Register::R9.register()),
        (10, Mips64Register::R10.register()),
        (11, Mips64Register::R11.register()),
        (12, Mips64Register::R12.register()),
        (13, Mips64Register::R13.register()),
        (14, Mips64Register::R14.register()),
        (15, Mips64Register::R15.register()),
        (16, Mips64Register::R16.register()),
        (17, Mips64Register::R17.register()),
        (18, Mips64Register::R18.register()),
        (19, Mips64Register::R19.register()),
        (20, Mips64Register::R20.register()),
        (21, Mips64Register::R21.register()),
        (22, Mips64Register::R22.register()),
        (23, Mips64Register::R23.register()),
        (24, Mips64Register::R24.register()),
        (25, Mips64Register::R25.register()),
        (26, Mips64Register::R26.register()),
        (27, Mips64Register::R27.register()),
        (28, Mips64Register::R28.register()),
        (29, Mips64Register::R29.register()),
        (30, Mips64Register::R30.register()),
        (31, Mips64Register::R31.register()),
        (33, Mips64Register::Lo.register()),
        (34, Mips64Register::Hi.register()),
        (37, Mips64Register::Pc.register()),
    ]);

    static ref MIPS64_CN_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from_iter([

    ]);
}

/// Mips64 Core Cpu
///
/// - No fpu
/// - No DSP
#[gdb_target_description]
#[derive(Debug, Default)]
pub struct Mips64CpuTargetDescription {
    #[args(
        gdb_arch_name("mips"),
        gdb_feature_xml(MIPS64_CPU),
        register_map(MIPS64_CPU_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::Mips64(Mips64Register::Pc))),
        endianness(ArchEndian::BigEndian)
    )]
    args: PhantomData<()>,
}

/// Mips64 Cavium Cpu
///
/// - No fpu
/// - No DSP
/// - **NOTE**: This Description currently only references
/// the core instruction. More work is needed to:
/// 1. find the correct xml formatting/ordering to cavium
/// 2. instead, make a custom xml we ship to gdb
#[gdb_target_description]
#[derive(Debug, Default)]
pub struct Mips64CaviumTargetDescription {
    #[args(
        gdb_arch_name("cnmips"),
        gdb_feature_xml(MIPS64_CPU),
        register_map(MIPS64_CPU_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::Mips64(Mips64Register::Pc))),
        endianness(ArchEndian::BigEndian)
    )]
    args: PhantomData<()>,
}
