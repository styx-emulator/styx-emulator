// BSD 2-Clause License
//
// Copyright (c) 2025, Styx Emulator Project
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

use std::collections::BTreeMap;

use super::HexagonRegister;
use crate::arch::backends::{ArchRegister, BasicArchRegister};
use crate::arch::CpuRegister;
use std::marker::PhantomData;
use styx_macros::gdb_target_description;
use styx_sync::lazy_static;
use styx_util::gdb_xml::HEXAGON_CORE;

lazy_static! {
    // Hexagon register map is not clear
    pub static ref HEXAGON_CORE_CPU_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, HexagonRegister::R0.register()),
        (1, HexagonRegister::R1.register()),
        (2, HexagonRegister::R2.register()),
        (3, HexagonRegister::R3.register()),
        (4, HexagonRegister::R4.register()),
        (5, HexagonRegister::R5.register()),
        (6, HexagonRegister::R6.register()),
        (7, HexagonRegister::R7.register()),
        (8, HexagonRegister::R8.register()),
        (9, HexagonRegister::R9.register()),
        (10, HexagonRegister::R10.register()),
        (11, HexagonRegister::R11.register()),
        (12, HexagonRegister::R12.register()),
        (13, HexagonRegister::R13.register()),
        (14, HexagonRegister::R14.register()),
        (15, HexagonRegister::R15.register()),
        (16, HexagonRegister::R16.register()),
        (17, HexagonRegister::R17.register()),
        (18, HexagonRegister::R18.register()),
        (19, HexagonRegister::R19.register()),
        (20, HexagonRegister::R20.register()),
        (21, HexagonRegister::R21.register()),
        (22, HexagonRegister::R22.register()),
        (23, HexagonRegister::R23.register()),
        (24, HexagonRegister::R24.register()),
        (25, HexagonRegister::R25.register()),
        (26, HexagonRegister::R26.register()),
        (27, HexagonRegister::R27.register()),
        (28, HexagonRegister::R28.register()),
        (29, HexagonRegister::Sp.register()),
        (30, HexagonRegister::Fp.register()),
        (31, HexagonRegister::Lr.register()),
        (32, HexagonRegister::Sa0.register()),
        (33, HexagonRegister::Lc0.register()),
        (34, HexagonRegister::Sa1.register()),
        (35, HexagonRegister::Lc1.register()),
        (36, HexagonRegister::P3_0.register()),
        (37, HexagonRegister::C5.register()),
        (38, HexagonRegister::M0.register()),
        (39, HexagonRegister::M1.register()),
        (40, HexagonRegister::Usr.register()),
        (41, HexagonRegister::Pc.register()),
        (42, HexagonRegister::Ugp.register()),
        (43, HexagonRegister::Gp.register()),
        (44, HexagonRegister::Cs0.register()),
        (45, HexagonRegister::Cs1.register()),
        (46, HexagonRegister::UpcycleLo.register()),
        (47, HexagonRegister::UpcycleHi.register()),
        (48, HexagonRegister::FrameLimit.register()),
        (49, HexagonRegister::FrameKey.register()),
        (50, HexagonRegister::PktCountLo.register()),
        (51, HexagonRegister::PktCountHi.register()),
        // START Reserved registers!
        (52, HexagonRegister::EmuPktCount.register()),
        (53, HexagonRegister::EmuInsnCount.register()),
        (54, HexagonRegister::EmuHvxCount.register()),
        // END Reserved registers!
        (55, HexagonRegister::C23.register()),
        (56, HexagonRegister::C24.register()),
        (57, HexagonRegister::C25.register()),
        (58, HexagonRegister::C26.register()),
        (59, HexagonRegister::C27.register()),
        (60, HexagonRegister::C28.register()),
        (61, HexagonRegister::C29.register()),
        (62, HexagonRegister::UtimerLo.register()),
        (63, HexagonRegister::UtimerHi.register())
    ]);
}

#[gdb_target_description]
#[derive(Debug, Default)]
pub struct HexagonCpuTargetDescription {
    #[args(
        // TODO: what should this be?
        gdb_arch_name("hexagon"),
        gdb_feature_xml(HEXAGON_CORE),
        register_map(HEXAGON_CORE_CPU_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::Hexagon(HexagonRegister::Pc))),
        endianness(ArchEndian::LittleEndian)
    )]
    args: PhantomData<()>,
}
