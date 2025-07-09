// SPDX-License-Identifier: BSD-2-Clause
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
