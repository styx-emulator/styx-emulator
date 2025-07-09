// SPDX-License-Identifier: BSD-2-Clause
//! `GDB` support macros and utilities for `ppc32` targets
use super::Msp430Register;
use crate::arch::backends::{ArchRegister, BasicArchRegister};
use crate::arch::msp430::Msp430XRegister;
use crate::arch::CpuRegister;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use styx_macros::gdb_target_description;
use styx_sync::lazy_static;
use styx_util::gdb_xml::{MSP430, MSP430X};

lazy_static! {
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    static ref MSP430_CPU_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, Msp430Register::R0.register()),
        (1, Msp430Register::R1.register()),
        (2, Msp430Register::R2.register()),
        (3, Msp430Register::R3.register()),
        (4, Msp430Register::R4.register()),
        (5, Msp430Register::R5.register()),
        (6, Msp430Register::R6.register()),
        (7, Msp430Register::R7.register()),
        (8, Msp430Register::R8.register()),
        (9, Msp430Register::R9.register()),
        (10, Msp430Register::R10.register()),
        (11, Msp430Register::R11.register()),
        (12, Msp430Register::R12.register()),
        (13, Msp430Register::R13.register()),
        (14, Msp430Register::R14.register()),
        (15, Msp430Register::R15.register()),
        (16, Msp430Register::Pc.register()),
        (17, Msp430Register::Sp.register()),
        (18, Msp430Register::Sr.register()),
    ]);


}

/// Msp430 Cpu
#[gdb_target_description]
#[derive(Debug, Default)]
pub struct Msp430CpuTargetDescription {
    #[args(
        gdb_arch_name("msp430"),
        gdb_feature_xml(MSP430),
        register_map(MSP430_CPU_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::Msp430(Msp430Register::Pc))),
        endianness(ArchEndian::LittleEndian)
    )]
    args: PhantomData<()>,
}

lazy_static! {
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    static ref MSP430X_CPU_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, Msp430XRegister::R0.register()),
        (1, Msp430XRegister::R1.register()),
        (2, Msp430XRegister::R2.register()),
        (3, Msp430XRegister::R3.register()),
        (4, Msp430XRegister::R4.register()),
        (5, Msp430XRegister::R5.register()),
        (6, Msp430XRegister::R6.register()),
        (7, Msp430XRegister::R7.register()),
        (8, Msp430XRegister::R8.register()),
        (9, Msp430XRegister::R9.register()),
        (10, Msp430XRegister::R10.register()),
        (11, Msp430XRegister::R11.register()),
        (12, Msp430XRegister::R12.register()),
        (13, Msp430XRegister::R13.register()),
        (14, Msp430XRegister::R14.register()),
        (15, Msp430XRegister::R15.register()),
        (16, Msp430XRegister::Pc.register()),
        (17, Msp430XRegister::Sp.register()),
        (18, Msp430XRegister::Sr.register()),
    ]);


}

/// Msp430 Cpu
#[gdb_target_description]
#[derive(Debug, Default)]
pub struct Msp430XCpuTargetDescription {
    #[args(
        gdb_arch_name("msp430x"),
        gdb_feature_xml(MSP430X),
        register_map(MSP430X_CPU_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::Msp430X(Msp430XRegister::Pc))),
        endianness(ArchEndian::LittleEndian)
    )]
    args: PhantomData<()>,
}
