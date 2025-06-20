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
use styx_util::gdb_xml::{HEXAGON_CORE, HEXAGON_HVX};

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

    // TODO: which variants have HVX, and which ones don't?
    static ref HEXAGON_HVX_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (88, HexagonRegister::V0.register()),
        (89, HexagonRegister::V1.register()),
        (90, HexagonRegister::V2.register()),
        (91, HexagonRegister::V3.register()),
        (92, HexagonRegister::V4.register()),
        (93, HexagonRegister::V5.register()),
        (94, HexagonRegister::V6.register()),
        (95, HexagonRegister::V7.register()),
        (96, HexagonRegister::V8.register()),
        (97, HexagonRegister::V9.register()),
        (98, HexagonRegister::V10.register()),
        (99, HexagonRegister::V11.register()),
        (100, HexagonRegister::V12.register()),
        (101, HexagonRegister::V13.register()),
        (102, HexagonRegister::V14.register()),
        (103, HexagonRegister::V15.register()),
        (104, HexagonRegister::V16.register()),
        (105, HexagonRegister::V17.register()),
        (106, HexagonRegister::V18.register()),
        (107, HexagonRegister::V19.register()),
        (108, HexagonRegister::V20.register()),
        (109, HexagonRegister::V21.register()),
        (110, HexagonRegister::V22.register()),
        (111, HexagonRegister::V23.register()),
        (112, HexagonRegister::V24.register()),
        (113, HexagonRegister::V25.register()),
        (114, HexagonRegister::V26.register()),
        (115, HexagonRegister::V27.register()),
        (116, HexagonRegister::V28.register()),
        (117, HexagonRegister::V29.register()),
        (118, HexagonRegister::V30.register()),
        (119, HexagonRegister::V31.register()),
        (120, HexagonRegister::Q0.register()),
        (121, HexagonRegister::Q1.register()),
        (122, HexagonRegister::Q2.register()),
        (123, HexagonRegister::Q3.register())
    ]);

    // Combine HVX register map and default register map
    pub static ref HEXAGON_CORE_HVX_CPU_REGISTER_MAP: BTreeMap<usize, CpuRegister> = HEXAGON_CORE_CPU_REGISTER_MAP
        .clone().into_iter().chain(HEXAGON_CORE_HVX_CPU_REGISTER_MAP.clone().into_iter()).collect();
}

#[gdb_target_description]
#[derive(Debug, Default)]
pub struct HexagonCpuTargetDescription {
    #[args(
        // TODO: what should this be?
        gdb_arch_name("hexagon-core"),
        gdb_feature_xml(HEXAGON_CORE),
        register_map(HEXAGON_CORE_CPU_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::Hexagon(HexagonRegister::Pc))),
        endianness(ArchEndian::LittleEndian)
    )]
    args: PhantomData<()>,
}

#[gdb_target_description]
#[derive(Debug, Default)]
pub struct HexagonHvxCpuTargetDescription {
    #[args(
        // TODO: what should this be?
        gdb_arch_name("hexagon-hvx"),
        gdb_feature_xml(HEXAGON_HVX),
        register_map(HEXAGON_CORE_HVX_CPU_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::Hexagon(HexagonRegister::Pc))),
        endianness(ArchEndian::LittleEndian)
    )]
    args: PhantomData<()>,
}
