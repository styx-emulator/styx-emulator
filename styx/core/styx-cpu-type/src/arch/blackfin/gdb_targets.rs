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
use super::BlackfinRegister;
use crate::arch::{
    backends::{ArchRegister, BasicArchRegister},
    CpuRegister,
};
use std::collections::BTreeMap;
use std::marker::PhantomData;
use styx_macros::gdb_target_description;
use styx_sync::lazy_static;
use styx_util::gdb_xml::BLACKFIN;

// register order found in `binutils-gdb/gdb/bfin-tdep.h` `enum gdb_regnum`
lazy_static! {
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    static ref BLACKFIN_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, BlackfinRegister::R0.register()),
        (1, BlackfinRegister::R1.register()),
        (2, BlackfinRegister::R2.register()),
        (3, BlackfinRegister::R3.register()),
        (4, BlackfinRegister::R4.register()),
        (5, BlackfinRegister::R5.register()),
        (6, BlackfinRegister::R6.register()),
        (7, BlackfinRegister::R7.register()),
        (8, BlackfinRegister::P0.register()),
        (9, BlackfinRegister::P1.register()),
        (10, BlackfinRegister::P2.register()),
        (11, BlackfinRegister::P3.register()),
        (12, BlackfinRegister::P4.register()),
        (13, BlackfinRegister::P5.register()),
        (14, BlackfinRegister::Sp.register()),
        (15, BlackfinRegister::Fp.register()),
        (16, BlackfinRegister::I0.register()),
        (17, BlackfinRegister::I1.register()),
        (18, BlackfinRegister::I2.register()),
        (19, BlackfinRegister::I3.register()),
        (20, BlackfinRegister::M0.register()),
        (21, BlackfinRegister::M1.register()),
        (22, BlackfinRegister::M2.register()),
        (23, BlackfinRegister::M3.register()),
        (24, BlackfinRegister::B0.register()),
        (25, BlackfinRegister::B1.register()),
        (26, BlackfinRegister::B2.register()),
        (27, BlackfinRegister::B3.register()),
        (28, BlackfinRegister::L0.register()),
        (29, BlackfinRegister::L1.register()),
        (30, BlackfinRegister::L2.register()),
        (31, BlackfinRegister::L3.register()),
        (32, BlackfinRegister::A0x.register()),
        (33, BlackfinRegister::A0w.register()),
        (34, BlackfinRegister::A1x.register()),
        (35, BlackfinRegister::A1w.register()),
        (36, BlackfinRegister::ASTAT.register()),
        (37, BlackfinRegister::RETS.register()),
        (38, BlackfinRegister::LC0.register()),
        (39, BlackfinRegister::LT0.register()),
        (40, BlackfinRegister::LB0.register()),
        (41, BlackfinRegister::LC1.register()),
        (42, BlackfinRegister::LT1.register()),
        (43, BlackfinRegister::LB1.register()),
        // (44, BlackfinRegister::CYCLES.register()),
        // (45, BlackfinRegister::CYCLES2.register()),
        // (46, BlackfinRegister::USP.register()),
        // (47, BlackfinRegister::SEQSTAT.register()),
        // (48, BlackfinRegister::SYSCFG.register()),
        (49, BlackfinRegister::RETI.register()),
        (50, BlackfinRegister::RETX.register()),
        (51, BlackfinRegister::RETN.register()),
        (52, BlackfinRegister::RETE.register()),
        (53, BlackfinRegister::Pc.register()),
        // (54, BlackfinRegister::CC.register())
    ]);
}

#[gdb_target_description]
#[derive(Debug, Default)]
pub struct BlackfinDescription {
    #[args(
        gdb_arch_name("bfin"),
        gdb_feature_xml(BLACKFIN),
        register_map(BLACKFIN_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::Blackfin(BlackfinRegister::Pc))),
        endianness(ArchEndian::LittleEndian)
    )]
    args: PhantomData<()>,
}
