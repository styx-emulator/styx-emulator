// SPDX-License-Identifier: BSD-2-Clause
//! `GDB` support macros and utilities for `ppc32` targets
use super::Ppc32Register;
use crate::arch::backends::{ArchRegister, BasicArchRegister};
use crate::arch::CpuRegister;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use styx_macros::gdb_target_description;
use styx_sync::lazy_static;
use styx_util::gdb_xml::POWER_CORE;

lazy_static! {
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    static ref POWER_CORE_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, Ppc32Register::R0.register()),
        (1, Ppc32Register::R1.register()),
        (2, Ppc32Register::R2.register()),
        (3, Ppc32Register::R3.register()),
        (4, Ppc32Register::R4.register()),
        (5, Ppc32Register::R5.register()),
        (6, Ppc32Register::R6.register()),
        (7, Ppc32Register::R7.register()),
        (8, Ppc32Register::R8.register()),
        (9, Ppc32Register::R9.register()),
        (10, Ppc32Register::R10.register()),
        (11, Ppc32Register::R11.register()),
        (12, Ppc32Register::R12.register()),
        (13, Ppc32Register::R13.register()),
        (14, Ppc32Register::R14.register()),
        (15, Ppc32Register::R15.register()),
        (16, Ppc32Register::R16.register()),
        (17, Ppc32Register::R17.register()),
        (18, Ppc32Register::R18.register()),
        (19, Ppc32Register::R19.register()),
        (20, Ppc32Register::R20.register()),
        (21, Ppc32Register::R21.register()),
        (22, Ppc32Register::R22.register()),
        (23, Ppc32Register::R23.register()),
        (24, Ppc32Register::R24.register()),
        (25, Ppc32Register::R25.register()),
        (26, Ppc32Register::R26.register()),
        (27, Ppc32Register::R27.register()),
        (28, Ppc32Register::R28.register()),
        (29, Ppc32Register::R29.register()),
        (30, Ppc32Register::R30.register()),
        (31, Ppc32Register::R31.register()),
        (64, Ppc32Register::Pc.register()),
        (65, Ppc32Register::Msr.register()),
        (66, Ppc32Register::Cr.register()),
        (67, Ppc32Register::Lr.register()),
        (68, Ppc32Register::Ctr.register()),
        (69, Ppc32Register::Xer.register()),
    ]);
}

// Ppc4xx
//
// Didn't see a more apt target than powerpc:403
#[gdb_target_description]
#[derive(Debug, Default)]
pub struct Ppc4xxTargetDescription {
    #[args(
        gdb_arch_name("powerpc:403"),
        gdb_feature_xml(POWER_CORE),
        register_map(POWER_CORE_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::Ppc32(Ppc32Register::Pc))),
        endianness(ArchEndian::BigEndian)
    )]
    args: PhantomData<()>,
}

#[gdb_target_description]
#[derive(Debug, Default)]
pub struct Mpc8xxTargetDescription {
    #[args(
        gdb_arch_name("powerpc:MPC8XX"),
        gdb_feature_xml(POWER_CORE),
        register_map(POWER_CORE_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::Ppc32(Ppc32Register::Pc))),
        endianness(ArchEndian::BigEndian)
    )]
    args: PhantomData<()>,
}
