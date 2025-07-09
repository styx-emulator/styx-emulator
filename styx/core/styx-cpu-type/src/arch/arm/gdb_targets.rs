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
//! `GDB` support macros and utilities for `Arm` targets
use super::ArmRegister;
use crate::arch::{
    backends::{ArchRegister, BasicArchRegister},
    CpuRegister,
};
use std::collections::BTreeMap;
use std::marker::PhantomData;
use styx_macros::gdb_target_description;
use styx_sync::lazy_static;
use styx_util::gdb_xml::{ARM_CORE, ARM_M_PROFILE};

lazy_static! {
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    pub static ref ARM_M_PROFILE_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, ArmRegister::R0.register()),
        (1, ArmRegister::R1.register()),
        (2, ArmRegister::R2.register()),
        (3, ArmRegister::R3.register()),
        (4, ArmRegister::R4.register()),
        (5, ArmRegister::R5.register()),
        (6, ArmRegister::R6.register()),
        (7, ArmRegister::R7.register()),
        (8, ArmRegister::R8.register()),
        (9, ArmRegister::R9.register()),
        (10, ArmRegister::R10.register()),
        (11, ArmRegister::R11.register()),
        (12, ArmRegister::R12.register()),
        (13, ArmRegister::Sp.register()),
        (14, ArmRegister::Lr.register()),
        (15, ArmRegister::Pc.register()),
        (25, ArmRegister::Xpsr.register()),
    ]);

    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    pub static ref ARM_CORE_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, ArmRegister::R0.register()),
        (1, ArmRegister::R1.register()),
        (2, ArmRegister::R2.register()),
        (3, ArmRegister::R3.register()),
        (4, ArmRegister::R4.register()),
        (5, ArmRegister::R5.register()),
        (6, ArmRegister::R6.register()),
        (7, ArmRegister::R7.register()),
        (8, ArmRegister::R8.register()),
        (9, ArmRegister::R9.register()),
        (10, ArmRegister::R10.register()),
        (11, ArmRegister::R11.register()),
        (12, ArmRegister::R12.register()),
        (13, ArmRegister::Sp.register()),
        (14, ArmRegister::Lr.register()),
        (15, ArmRegister::Pc.register()),
        (25, ArmRegister::Cpsr.register()),
    ]);
}

#[gdb_target_description]
#[derive(Debug, Default)]
pub struct Armv7emDescription {
    #[args(
        gdb_arch_name("armv7e-m"),
        gdb_feature_xml(ARM_M_PROFILE),
        register_map(ARM_M_PROFILE_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::Arm(ArmRegister::Pc))),
        endianness(ArchEndian::LittleEndian)
    )]
    args: PhantomData<()>,
}

#[gdb_target_description]
#[derive(Debug, Default)]
pub struct ArmMProfileDescription {
    #[args(
        gdb_arch_name("arm"),
        gdb_feature_xml(ARM_M_PROFILE),
        register_map(ARM_M_PROFILE_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::Arm(ArmRegister::Pc))),
        endianness(ArchEndian::LittleEndian)
    )]
    args: PhantomData<()>,
}

#[gdb_target_description]
#[derive(Debug, Default)]
pub struct ArmCoreDescription {
    #[args(
        gdb_arch_name("arm"),
        gdb_feature_xml(ARM_CORE),
        register_map(ARM_CORE_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::Arm(ArmRegister::Pc))),
        endianness(ArchEndian::LittleEndian)
    )]
    args: PhantomData<()>,
}
