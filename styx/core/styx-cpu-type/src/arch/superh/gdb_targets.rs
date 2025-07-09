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
//! `GDB` support macros and utilities for `SuperH` targets
use super::SuperHRegister;
use crate::arch::{
    backends::{ArchRegister, BasicArchRegister},
    CpuRegister,
};
use std::collections::BTreeMap;
use std::marker::PhantomData;
use styx_macros::gdb_target_description;
use styx_sync::lazy_static;
use styx_util::gdb_xml::*;

lazy_static! {
    /// SH
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    pub static ref SH_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, SuperHRegister::R0.register()),
        (1, SuperHRegister::R1.register()),
        (2, SuperHRegister::R2.register()),
        (3, SuperHRegister::R3.register()),
        (4, SuperHRegister::R4.register()),
        (5, SuperHRegister::R5.register()),
        (6, SuperHRegister::R6.register()),
        (7, SuperHRegister::R7.register()),
        (8, SuperHRegister::R8.register()),
        (9, SuperHRegister::R9.register()),
        (10, SuperHRegister::R10.register()),
        (11, SuperHRegister::R11.register()),
        (12, SuperHRegister::R12.register()),
        (13, SuperHRegister::R13.register()),
        (14, SuperHRegister::R14.register()),
        (15, SuperHRegister::R15.register()),
        (16, SuperHRegister::Pc.register()),
        (17, SuperHRegister::Pr.register()),
        (18, SuperHRegister::Gbr.register()),
        (19, SuperHRegister::Vbr.register()),
        (20, SuperHRegister::Mach.register()),
        (21, SuperHRegister::Macl.register()),
        (22, SuperHRegister::Sr.register()),
    ]);
    /// SH-DSP
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    pub static ref SH_DSP_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, SuperHRegister::R0.register()),
        (1, SuperHRegister::R1.register()),
        (2, SuperHRegister::R2.register()),
        (3, SuperHRegister::R3.register()),
        (4, SuperHRegister::R4.register()),
        (5, SuperHRegister::R5.register()),
        (6, SuperHRegister::R6.register()),
        (7, SuperHRegister::R7.register()),
        (8, SuperHRegister::R8.register()),
        (9, SuperHRegister::R9.register()),
        (10, SuperHRegister::R10.register()),
        (11, SuperHRegister::R11.register()),
        (12, SuperHRegister::R12.register()),
        (13, SuperHRegister::R13.register()),
        (14, SuperHRegister::R14.register()),
        (15, SuperHRegister::R15.register()),
        (16, SuperHRegister::Pc.register()),
        (17, SuperHRegister::Pr.register()),
        (18, SuperHRegister::Gbr.register()),
        (19, SuperHRegister::Vbr.register()),
        (20, SuperHRegister::Mach.register()),
        (21, SuperHRegister::Macl.register()),
        (22, SuperHRegister::Sr.register()),
        (24, SuperHRegister::Dsr.register()),
        (25, SuperHRegister::A0g.register()),
        (26, SuperHRegister::A0.register()),
        (27, SuperHRegister::A1g.register()),
        (28, SuperHRegister::A1.register()),
        (29, SuperHRegister::M0.register()),
        (30, SuperHRegister::M1.register()),
        (31, SuperHRegister::X0.register()),
        (32, SuperHRegister::X1.register()),
        (33, SuperHRegister::Y0.register()),
        (34, SuperHRegister::Y1.register()),
        (40, SuperHRegister::Mod.register()),
        (43, SuperHRegister::Rs.register()),
        (44, SuperHRegister::Re.register()),
    ]);
    /// SH2
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    pub static ref SH2_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, SuperHRegister::R0.register()),
        (1, SuperHRegister::R1.register()),
        (2, SuperHRegister::R2.register()),
        (3, SuperHRegister::R3.register()),
        (4, SuperHRegister::R4.register()),
        (5, SuperHRegister::R5.register()),
        (6, SuperHRegister::R6.register()),
        (7, SuperHRegister::R7.register()),
        (8, SuperHRegister::R8.register()),
        (9, SuperHRegister::R9.register()),
        (10, SuperHRegister::R10.register()),
        (11, SuperHRegister::R11.register()),
        (12, SuperHRegister::R12.register()),
        (13, SuperHRegister::R13.register()),
        (14, SuperHRegister::R14.register()),
        (15, SuperHRegister::R15.register()),
        (16, SuperHRegister::Pc.register()),
        (17, SuperHRegister::Pr.register()),
        (18, SuperHRegister::Gbr.register()),
        (19, SuperHRegister::Vbr.register()),
        (20, SuperHRegister::Mach.register()),
        (21, SuperHRegister::Macl.register()),
        (22, SuperHRegister::Sr.register()),
    ]);
    /// SH2A
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    pub static ref SH2A_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, SuperHRegister::R0.register()),
        (1, SuperHRegister::R1.register()),
        (2, SuperHRegister::R2.register()),
        (3, SuperHRegister::R3.register()),
        (4, SuperHRegister::R4.register()),
        (5, SuperHRegister::R5.register()),
        (6, SuperHRegister::R6.register()),
        (7, SuperHRegister::R7.register()),
        (8, SuperHRegister::R8.register()),
        (9, SuperHRegister::R9.register()),
        (10, SuperHRegister::R10.register()),
        (11, SuperHRegister::R11.register()),
        (12, SuperHRegister::R12.register()),
        (13, SuperHRegister::R13.register()),
        (14, SuperHRegister::R14.register()),
        (15, SuperHRegister::R15.register()),
        (16, SuperHRegister::Pc.register()),
        (17, SuperHRegister::Pr.register()),
        (18, SuperHRegister::Gbr.register()),
        (19, SuperHRegister::Vbr.register()),
        (20, SuperHRegister::Mach.register()),
        (21, SuperHRegister::Macl.register()),
        (22, SuperHRegister::Sr.register()),
        (23, SuperHRegister::Fpul.register()),
        (24, SuperHRegister::Fpscr.register()),
        (25, SuperHRegister::Fr0.register()),
        (26, SuperHRegister::Fr1.register()),
        (27, SuperHRegister::Fr2.register()),
        (28, SuperHRegister::Fr3.register()),
        (29, SuperHRegister::Fr4.register()),
        (30, SuperHRegister::Fr5.register()),
        (31, SuperHRegister::Fr6.register()),
        (32, SuperHRegister::Fr7.register()),
        (33, SuperHRegister::Fr8.register()),
        (34, SuperHRegister::Fr9.register()),
        (35, SuperHRegister::Fr10.register()),
        (36, SuperHRegister::Fr11.register()),
        (37, SuperHRegister::Fr12.register()),
        (38, SuperHRegister::Fr13.register()),
        (39, SuperHRegister::Fr14.register()),
        (40, SuperHRegister::Fr15.register()),
        (43, SuperHRegister::R0b.register()),
        (44, SuperHRegister::R1b.register()),
        (45, SuperHRegister::R2b.register()),
        (46, SuperHRegister::R3b.register()),
        (47, SuperHRegister::R4b.register()),
        (48, SuperHRegister::R5b.register()),
        (49, SuperHRegister::R6b.register()),
        (50, SuperHRegister::R7b.register()),
        (51, SuperHRegister::R8b.register()),
        (52, SuperHRegister::R9b.register()),
        (53, SuperHRegister::R10b.register()),
        (54, SuperHRegister::R11b.register()),
        (55, SuperHRegister::R12b.register()),
        (56, SuperHRegister::R13b.register()),
        (57, SuperHRegister::R14b.register()),
        (58, SuperHRegister::Machb.register()),
        (59, SuperHRegister::Ivnb.register()),
        (60, SuperHRegister::Prb.register()),
        (61, SuperHRegister::Gbrb.register()),
        (62, SuperHRegister::Maclb.register()),
        (64, SuperHRegister::Ibcr.register()),
        (65, SuperHRegister::Ibnr.register()),
        (66, SuperHRegister::Tbr.register()),
        (67, SuperHRegister::Bank.register()),
        (68, SuperHRegister::Dr0.register()),
        (69, SuperHRegister::Dr2.register()),
        (70, SuperHRegister::Dr4.register()),
        (71, SuperHRegister::Dr6.register()),
        (72, SuperHRegister::Dr8.register()),
        (73, SuperHRegister::Dr10.register()),
        (74, SuperHRegister::Dr12.register()),
        (75, SuperHRegister::Dr14.register()),
    ]);
    /// SH2-no-FPU (2a no fpu)
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    pub static ref SH2A_NOFPU_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, SuperHRegister::R0.register()),
        (1, SuperHRegister::R1.register()),
        (2, SuperHRegister::R2.register()),
        (3, SuperHRegister::R3.register()),
        (4, SuperHRegister::R4.register()),
        (5, SuperHRegister::R5.register()),
        (6, SuperHRegister::R6.register()),
        (7, SuperHRegister::R7.register()),
        (8, SuperHRegister::R8.register()),
        (9, SuperHRegister::R9.register()),
        (10, SuperHRegister::R10.register()),
        (11, SuperHRegister::R11.register()),
        (12, SuperHRegister::R12.register()),
        (13, SuperHRegister::R13.register()),
        (14, SuperHRegister::R14.register()),
        (15, SuperHRegister::R15.register()),
        (16, SuperHRegister::Pc.register()),
        (17, SuperHRegister::Pr.register()),
        (18, SuperHRegister::Gbr.register()),
        (19, SuperHRegister::Vbr.register()),
        (20, SuperHRegister::Mach.register()),
        (21, SuperHRegister::Macl.register()),
        (22, SuperHRegister::Sr.register()),
        (43, SuperHRegister::R0b.register()),
        (44, SuperHRegister::R1b.register()),
        (45, SuperHRegister::R2b.register()),
        (46, SuperHRegister::R3b.register()),
        (47, SuperHRegister::R4b.register()),
        (48, SuperHRegister::R5b.register()),
        (49, SuperHRegister::R6b.register()),
        (50, SuperHRegister::R7b.register()),
        (51, SuperHRegister::R8b.register()),
        (52, SuperHRegister::R9b.register()),
        (53, SuperHRegister::R10b.register()),
        (54, SuperHRegister::R11b.register()),
        (55, SuperHRegister::R12b.register()),
        (56, SuperHRegister::R13b.register()),
        (57, SuperHRegister::R14b.register()),
        (58, SuperHRegister::Machb.register()),
        (59, SuperHRegister::Ivnb.register()),
        (60, SuperHRegister::Prb.register()),
        (61, SuperHRegister::Gbrb.register()),
        (62, SuperHRegister::Maclb.register()),
        (64, SuperHRegister::Ibcr.register()),
        (65, SuperHRegister::Ibnr.register()),
        (66, SuperHRegister::Tbr.register()),
        (67, SuperHRegister::Bank.register()),
    ]);
    /// SH2e (2a no register bank)
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    pub static ref SH2E_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, SuperHRegister::R0.register()),
        (1, SuperHRegister::R1.register()),
        (2, SuperHRegister::R2.register()),
        (3, SuperHRegister::R3.register()),
        (4, SuperHRegister::R4.register()),
        (5, SuperHRegister::R5.register()),
        (6, SuperHRegister::R6.register()),
        (7, SuperHRegister::R7.register()),
        (8, SuperHRegister::R8.register()),
        (9, SuperHRegister::R9.register()),
        (10, SuperHRegister::R10.register()),
        (11, SuperHRegister::R11.register()),
        (12, SuperHRegister::R12.register()),
        (13, SuperHRegister::R13.register()),
        (14, SuperHRegister::R14.register()),
        (15, SuperHRegister::R15.register()),
        (16, SuperHRegister::Pc.register()),
        (17, SuperHRegister::Pr.register()),
        (18, SuperHRegister::Gbr.register()),
        (19, SuperHRegister::Vbr.register()),
        (20, SuperHRegister::Mach.register()),
        (21, SuperHRegister::Macl.register()),
        (22, SuperHRegister::Sr.register()),
        (23, SuperHRegister::Fpul.register()),
        (24, SuperHRegister::Fpscr.register()),
        (25, SuperHRegister::Fr0.register()),
        (26, SuperHRegister::Fr1.register()),
        (27, SuperHRegister::Fr2.register()),
        (28, SuperHRegister::Fr3.register()),
        (29, SuperHRegister::Fr4.register()),
        (30, SuperHRegister::Fr5.register()),
        (31, SuperHRegister::Fr6.register()),
        (32, SuperHRegister::Fr7.register()),
        (33, SuperHRegister::Fr8.register()),
        (34, SuperHRegister::Fr9.register()),
        (35, SuperHRegister::Fr10.register()),
        (36, SuperHRegister::Fr11.register()),
        (37, SuperHRegister::Fr12.register()),
        (38, SuperHRegister::Fr13.register()),
        (39, SuperHRegister::Fr14.register()),
        (40, SuperHRegister::Fr15.register()),
    ]);
    // SH3 (same registers as SH3-NOMMU)
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    pub static ref SH3_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, SuperHRegister::R0.register()),
        (1, SuperHRegister::R1.register()),
        (2, SuperHRegister::R2.register()),
        (3, SuperHRegister::R3.register()),
        (4, SuperHRegister::R4.register()),
        (5, SuperHRegister::R5.register()),
        (6, SuperHRegister::R6.register()),
        (7, SuperHRegister::R7.register()),
        (8, SuperHRegister::R8.register()),
        (9, SuperHRegister::R9.register()),
        (10, SuperHRegister::R10.register()),
        (11, SuperHRegister::R11.register()),
        (12, SuperHRegister::R12.register()),
        (13, SuperHRegister::R13.register()),
        (14, SuperHRegister::R14.register()),
        (15, SuperHRegister::R15.register()),
        (16, SuperHRegister::Pc.register()),
        (17, SuperHRegister::Pr.register()),
        (18, SuperHRegister::Gbr.register()),
        (19, SuperHRegister::Vbr.register()),
        (20, SuperHRegister::Mach.register()),
        (21, SuperHRegister::Macl.register()),
        (22, SuperHRegister::Sr.register()),
        (41, SuperHRegister::Ssr.register()),
        (42, SuperHRegister::Spc.register()),
        (43, SuperHRegister::R0b0.register()),
        (44, SuperHRegister::R1b0.register()),
        (45, SuperHRegister::R2b0.register()),
        (46, SuperHRegister::R3b0.register()),
        (47, SuperHRegister::R4b0.register()),
        (48, SuperHRegister::R5b0.register()),
        (49, SuperHRegister::R6b0.register()),
        (50, SuperHRegister::R7b0.register()),
        (51, SuperHRegister::R0b1.register()),
        (52, SuperHRegister::R1b1.register()),
        (53, SuperHRegister::R2b1.register()),
        (54, SuperHRegister::R3b1.register()),
        (55, SuperHRegister::R4b1.register()),
        (56, SuperHRegister::R5b1.register()),
        (57, SuperHRegister::R6b1.register()),
        (58, SuperHRegister::R7b1.register()),
    ]);
    /// SH3e (3 + FPU)
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    pub static ref SH3E_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, SuperHRegister::R0.register()),
        (1, SuperHRegister::R1.register()),
        (2, SuperHRegister::R2.register()),
        (3, SuperHRegister::R3.register()),
        (4, SuperHRegister::R4.register()),
        (5, SuperHRegister::R5.register()),
        (6, SuperHRegister::R6.register()),
        (7, SuperHRegister::R7.register()),
        (8, SuperHRegister::R8.register()),
        (9, SuperHRegister::R9.register()),
        (10, SuperHRegister::R10.register()),
        (11, SuperHRegister::R11.register()),
        (12, SuperHRegister::R12.register()),
        (13, SuperHRegister::R13.register()),
        (14, SuperHRegister::R14.register()),
        (15, SuperHRegister::R15.register()),
        (16, SuperHRegister::Pc.register()),
        (17, SuperHRegister::Pr.register()),
        (18, SuperHRegister::Gbr.register()),
        (19, SuperHRegister::Vbr.register()),
        (20, SuperHRegister::Mach.register()),
        (21, SuperHRegister::Macl.register()),
        (22, SuperHRegister::Sr.register()),
        (23, SuperHRegister::Fpul.register()),
        (24, SuperHRegister::Fpscr.register()),
        (25, SuperHRegister::Fr0.register()),
        (26, SuperHRegister::Fr1.register()),
        (27, SuperHRegister::Fr2.register()),
        (28, SuperHRegister::Fr3.register()),
        (29, SuperHRegister::Fr4.register()),
        (30, SuperHRegister::Fr5.register()),
        (31, SuperHRegister::Fr6.register()),
        (32, SuperHRegister::Fr7.register()),
        (33, SuperHRegister::Fr8.register()),
        (34, SuperHRegister::Fr9.register()),
        (35, SuperHRegister::Fr10.register()),
        (36, SuperHRegister::Fr11.register()),
        (37, SuperHRegister::Fr12.register()),
        (38, SuperHRegister::Fr13.register()),
        (39, SuperHRegister::Fr14.register()),
        (40, SuperHRegister::Fr15.register()),
        (41, SuperHRegister::Ssr.register()),
        (42, SuperHRegister::Spc.register()),
        (43, SuperHRegister::R0b0.register()),
        (44, SuperHRegister::R1b0.register()),
        (45, SuperHRegister::R2b0.register()),
        (46, SuperHRegister::R3b0.register()),
        (47, SuperHRegister::R4b0.register()),
        (48, SuperHRegister::R5b0.register()),
        (49, SuperHRegister::R6b0.register()),
        (50, SuperHRegister::R7b0.register()),
        (51, SuperHRegister::R0b1.register()),
        (52, SuperHRegister::R1b1.register()),
        (53, SuperHRegister::R2b1.register()),
        (54, SuperHRegister::R3b1.register()),
        (55, SuperHRegister::R4b1.register()),
        (56, SuperHRegister::R5b1.register()),
        (57, SuperHRegister::R6b1.register()),
        (58, SuperHRegister::R7b1.register()),
    ]);
    /// SH3-DSP
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    pub static ref SH3_DSP_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, SuperHRegister::R0.register()),
        (1, SuperHRegister::R1.register()),
        (2, SuperHRegister::R2.register()),
        (3, SuperHRegister::R3.register()),
        (4, SuperHRegister::R4.register()),
        (5, SuperHRegister::R5.register()),
        (6, SuperHRegister::R6.register()),
        (7, SuperHRegister::R7.register()),
        (8, SuperHRegister::R8.register()),
        (9, SuperHRegister::R9.register()),
        (10, SuperHRegister::R10.register()),
        (11, SuperHRegister::R11.register()),
        (12, SuperHRegister::R12.register()),
        (13, SuperHRegister::R13.register()),
        (14, SuperHRegister::R14.register()),
        (15, SuperHRegister::R15.register()),
        (16, SuperHRegister::Pc.register()),
        (17, SuperHRegister::Pr.register()),
        (18, SuperHRegister::Gbr.register()),
        (19, SuperHRegister::Vbr.register()),
        (20, SuperHRegister::Mach.register()),
        (21, SuperHRegister::Macl.register()),
        (22, SuperHRegister::Sr.register()),
        (24, SuperHRegister::Dsr.register()),
        (25, SuperHRegister::A0g.register()),
        (26, SuperHRegister::A0.register()),
        (27, SuperHRegister::A1g.register()),
        (28, SuperHRegister::A1.register()),
        (29, SuperHRegister::M0.register()),
        (30, SuperHRegister::M1.register()),
        (31, SuperHRegister::X0.register()),
        (32, SuperHRegister::X1.register()),
        (33, SuperHRegister::Y0.register()),
        (34, SuperHRegister::Y1.register()),
        (40, SuperHRegister::Mod.register()),
        (41, SuperHRegister::Ssr.register()),
        (42, SuperHRegister::Spc.register()),
        (43, SuperHRegister::Rs.register()),
        (44, SuperHRegister::Re.register()),
        (51, SuperHRegister::R0b.register()),
        (52, SuperHRegister::R1b.register()),
        (53, SuperHRegister::R2b.register()),
        (54, SuperHRegister::R3b.register()),
        (55, SuperHRegister::R4b.register()),
        (56, SuperHRegister::R5b.register()),
        (57, SuperHRegister::R6b.register()),
        (58, SuperHRegister::R7b.register()),
    ]);
    /// SH4
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    pub static ref SH4_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, SuperHRegister::R0.register()),
        (1, SuperHRegister::R1.register()),
        (2, SuperHRegister::R2.register()),
        (3, SuperHRegister::R3.register()),
        (4, SuperHRegister::R4.register()),
        (5, SuperHRegister::R5.register()),
        (6, SuperHRegister::R6.register()),
        (7, SuperHRegister::R7.register()),
        (8, SuperHRegister::R8.register()),
        (9, SuperHRegister::R9.register()),
        (10, SuperHRegister::R10.register()),
        (11, SuperHRegister::R11.register()),
        (12, SuperHRegister::R12.register()),
        (13, SuperHRegister::R13.register()),
        (14, SuperHRegister::R14.register()),
        (15, SuperHRegister::R15.register()),
        (16, SuperHRegister::Pc.register()),
        (17, SuperHRegister::Pr.register()),
        (18, SuperHRegister::Gbr.register()),
        (19, SuperHRegister::Vbr.register()),
        (20, SuperHRegister::Mach.register()),
        (21, SuperHRegister::Macl.register()),
        (22, SuperHRegister::Sr.register()),
        (23, SuperHRegister::Fpul.register()),
        (24, SuperHRegister::Fpscr.register()),
        (25, SuperHRegister::Fr0.register()),
        (26, SuperHRegister::Fr1.register()),
        (27, SuperHRegister::Fr2.register()),
        (28, SuperHRegister::Fr3.register()),
        (29, SuperHRegister::Fr4.register()),
        (30, SuperHRegister::Fr5.register()),
        (31, SuperHRegister::Fr6.register()),
        (32, SuperHRegister::Fr7.register()),
        (33, SuperHRegister::Fr8.register()),
        (34, SuperHRegister::Fr9.register()),
        (35, SuperHRegister::Fr10.register()),
        (36, SuperHRegister::Fr11.register()),
        (37, SuperHRegister::Fr12.register()),
        (38, SuperHRegister::Fr13.register()),
        (39, SuperHRegister::Fr14.register()),
        (40, SuperHRegister::Fr15.register()),
        (41, SuperHRegister::Ssr.register()),
        (42, SuperHRegister::Spc.register()),
        (43, SuperHRegister::R0b0.register()),
        (44, SuperHRegister::R1b0.register()),
        (45, SuperHRegister::R2b0.register()),
        (46, SuperHRegister::R3b0.register()),
        (47, SuperHRegister::R4b0.register()),
        (48, SuperHRegister::R5b0.register()),
        (49, SuperHRegister::R6b0.register()),
        (50, SuperHRegister::R7b0.register()),
        (51, SuperHRegister::R0b1.register()),
        (52, SuperHRegister::R1b1.register()),
        (53, SuperHRegister::R2b1.register()),
        (54, SuperHRegister::R3b1.register()),
        (55, SuperHRegister::R4b1.register()),
        (56, SuperHRegister::R5b1.register()),
        (57, SuperHRegister::R6b1.register()),
        (58, SuperHRegister::R7b1.register()),
        (68, SuperHRegister::Dr0.register()),
        (69, SuperHRegister::Dr2.register()),
        (70, SuperHRegister::Dr4.register()),
        (71, SuperHRegister::Dr6.register()),
        (72, SuperHRegister::Dr8.register()),
        (73, SuperHRegister::Dr10.register()),
        (74, SuperHRegister::Dr12.register()),
        (75, SuperHRegister::Dr14.register()),
        (76, SuperHRegister::Fv0.register()),
        (77, SuperHRegister::Fv4.register()),
        (78, SuperHRegister::Fv8.register()),
        (79, SuperHRegister::Fv12.register()),
    ]);
    /// SH4-no-FPU
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    pub static ref SH4_NOFPU_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, SuperHRegister::R0.register()),
        (1, SuperHRegister::R1.register()),
        (2, SuperHRegister::R2.register()),
        (3, SuperHRegister::R3.register()),
        (4, SuperHRegister::R4.register()),
        (5, SuperHRegister::R5.register()),
        (6, SuperHRegister::R6.register()),
        (7, SuperHRegister::R7.register()),
        (8, SuperHRegister::R8.register()),
        (9, SuperHRegister::R9.register()),
        (10, SuperHRegister::R10.register()),
        (11, SuperHRegister::R11.register()),
        (12, SuperHRegister::R12.register()),
        (13, SuperHRegister::R13.register()),
        (14, SuperHRegister::R14.register()),
        (15, SuperHRegister::R15.register()),
        (16, SuperHRegister::Pc.register()),
        (17, SuperHRegister::Pr.register()),
        (18, SuperHRegister::Gbr.register()),
        (19, SuperHRegister::Vbr.register()),
        (20, SuperHRegister::Mach.register()),
        (21, SuperHRegister::Macl.register()),
        (22, SuperHRegister::Sr.register()),
        (41, SuperHRegister::Ssr.register()),
        (42, SuperHRegister::Spc.register()),
        (43, SuperHRegister::R0b0.register()),
        (44, SuperHRegister::R1b0.register()),
        (45, SuperHRegister::R2b0.register()),
        (46, SuperHRegister::R3b0.register()),
        (47, SuperHRegister::R4b0.register()),
        (48, SuperHRegister::R5b0.register()),
        (49, SuperHRegister::R6b0.register()),
        (50, SuperHRegister::R7b0.register()),
        (51, SuperHRegister::R0b1.register()),
        (52, SuperHRegister::R1b1.register()),
        (53, SuperHRegister::R2b1.register()),
        (54, SuperHRegister::R3b1.register()),
        (55, SuperHRegister::R4b1.register()),
        (56, SuperHRegister::R5b1.register()),
        (57, SuperHRegister::R6b1.register()),
        (58, SuperHRegister::R7b1.register()),
    ]);
    /// SH4a == SH4
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    pub static ref SH4A_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, SuperHRegister::R0.register()),
        (1, SuperHRegister::R1.register()),
        (2, SuperHRegister::R2.register()),
        (3, SuperHRegister::R3.register()),
        (4, SuperHRegister::R4.register()),
        (5, SuperHRegister::R5.register()),
        (6, SuperHRegister::R6.register()),
        (7, SuperHRegister::R7.register()),
        (8, SuperHRegister::R8.register()),
        (9, SuperHRegister::R9.register()),
        (10, SuperHRegister::R10.register()),
        (11, SuperHRegister::R11.register()),
        (12, SuperHRegister::R12.register()),
        (13, SuperHRegister::R13.register()),
        (14, SuperHRegister::R14.register()),
        (15, SuperHRegister::R15.register()),
        (16, SuperHRegister::Pc.register()),
        (17, SuperHRegister::Pr.register()),
        (18, SuperHRegister::Gbr.register()),
        (19, SuperHRegister::Vbr.register()),
        (20, SuperHRegister::Mach.register()),
        (21, SuperHRegister::Macl.register()),
        (22, SuperHRegister::Sr.register()),
        (23, SuperHRegister::Fpul.register()),
        (24, SuperHRegister::Fpscr.register()),
        (25, SuperHRegister::Fr0.register()),
        (26, SuperHRegister::Fr1.register()),
        (27, SuperHRegister::Fr2.register()),
        (28, SuperHRegister::Fr3.register()),
        (29, SuperHRegister::Fr4.register()),
        (30, SuperHRegister::Fr5.register()),
        (31, SuperHRegister::Fr6.register()),
        (32, SuperHRegister::Fr7.register()),
        (33, SuperHRegister::Fr8.register()),
        (34, SuperHRegister::Fr9.register()),
        (35, SuperHRegister::Fr10.register()),
        (36, SuperHRegister::Fr11.register()),
        (37, SuperHRegister::Fr12.register()),
        (38, SuperHRegister::Fr13.register()),
        (39, SuperHRegister::Fr14.register()),
        (40, SuperHRegister::Fr15.register()),
        (41, SuperHRegister::Ssr.register()),
        (42, SuperHRegister::Spc.register()),
        (43, SuperHRegister::R0b0.register()),
        (44, SuperHRegister::R1b0.register()),
        (45, SuperHRegister::R2b0.register()),
        (46, SuperHRegister::R3b0.register()),
        (47, SuperHRegister::R4b0.register()),
        (48, SuperHRegister::R5b0.register()),
        (49, SuperHRegister::R6b0.register()),
        (50, SuperHRegister::R7b0.register()),
        (51, SuperHRegister::R0b1.register()),
        (52, SuperHRegister::R1b1.register()),
        (53, SuperHRegister::R2b1.register()),
        (54, SuperHRegister::R3b1.register()),
        (55, SuperHRegister::R4b1.register()),
        (56, SuperHRegister::R5b1.register()),
        (57, SuperHRegister::R6b1.register()),
        (58, SuperHRegister::R7b1.register()),
        (68, SuperHRegister::Dr0.register()),
        (69, SuperHRegister::Dr2.register()),
        (70, SuperHRegister::Dr4.register()),
        (71, SuperHRegister::Dr6.register()),
        (72, SuperHRegister::Dr8.register()),
        (73, SuperHRegister::Dr10.register()),
        (74, SuperHRegister::Dr12.register()),
        (75, SuperHRegister::Dr14.register()),
        (76, SuperHRegister::Fv0.register()),
        (77, SuperHRegister::Fv4.register()),
        (78, SuperHRegister::Fv8.register()),
        (79, SuperHRegister::Fv12.register()),
    ]);
    /// SH4a nofpu
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    pub static ref SH4A_NOFPU_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, SuperHRegister::R0.register()),
        (1, SuperHRegister::R1.register()),
        (2, SuperHRegister::R2.register()),
        (3, SuperHRegister::R3.register()),
        (4, SuperHRegister::R4.register()),
        (5, SuperHRegister::R5.register()),
        (6, SuperHRegister::R6.register()),
        (7, SuperHRegister::R7.register()),
        (8, SuperHRegister::R8.register()),
        (9, SuperHRegister::R9.register()),
        (10, SuperHRegister::R10.register()),
        (11, SuperHRegister::R11.register()),
        (12, SuperHRegister::R12.register()),
        (13, SuperHRegister::R13.register()),
        (14, SuperHRegister::R14.register()),
        (15, SuperHRegister::R15.register()),
        (16, SuperHRegister::Pc.register()),
        (17, SuperHRegister::Pr.register()),
        (18, SuperHRegister::Gbr.register()),
        (19, SuperHRegister::Vbr.register()),
        (20, SuperHRegister::Mach.register()),
        (21, SuperHRegister::Macl.register()),
        (22, SuperHRegister::Sr.register()),
        (41, SuperHRegister::Ssr.register()),
        (42, SuperHRegister::Spc.register()),
        (43, SuperHRegister::R0b0.register()),
        (44, SuperHRegister::R1b0.register()),
        (45, SuperHRegister::R2b0.register()),
        (46, SuperHRegister::R3b0.register()),
        (47, SuperHRegister::R4b0.register()),
        (48, SuperHRegister::R5b0.register()),
        (49, SuperHRegister::R6b0.register()),
        (50, SuperHRegister::R7b0.register()),
        (51, SuperHRegister::R0b1.register()),
        (52, SuperHRegister::R1b1.register()),
        (53, SuperHRegister::R2b1.register()),
        (54, SuperHRegister::R3b1.register()),
        (55, SuperHRegister::R4b1.register()),
        (56, SuperHRegister::R5b1.register()),
        (57, SuperHRegister::R6b1.register()),
        (58, SuperHRegister::R7b1.register()),
    ]);

    /// SH4al-DSP
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    pub static ref SH4AL_DSP_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, SuperHRegister::R0.register()),
        (1, SuperHRegister::R1.register()),
        (2, SuperHRegister::R2.register()),
        (3, SuperHRegister::R3.register()),
        (4, SuperHRegister::R4.register()),
        (5, SuperHRegister::R5.register()),
        (6, SuperHRegister::R6.register()),
        (7, SuperHRegister::R7.register()),
        (8, SuperHRegister::R8.register()),
        (9, SuperHRegister::R9.register()),
        (10, SuperHRegister::R10.register()),
        (11, SuperHRegister::R11.register()),
        (12, SuperHRegister::R12.register()),
        (13, SuperHRegister::R13.register()),
        (14, SuperHRegister::R14.register()),
        (15, SuperHRegister::R15.register()),
        (16, SuperHRegister::Pc.register()),
        (17, SuperHRegister::Pr.register()),
        (18, SuperHRegister::Gbr.register()),
        (19, SuperHRegister::Vbr.register()),
        (20, SuperHRegister::Mach.register()),
        (21, SuperHRegister::Macl.register()),
        (22, SuperHRegister::Sr.register()),
        (24, SuperHRegister::Dsr.register()),
        (25, SuperHRegister::A0g.register()),
        (26, SuperHRegister::A0.register()),
        (27, SuperHRegister::A1g.register()),
        (28, SuperHRegister::A1.register()),
        (29, SuperHRegister::M0.register()),
        (30, SuperHRegister::M1.register()),
        (31, SuperHRegister::X0.register()),
        (32, SuperHRegister::X1.register()),
        (33, SuperHRegister::Y0.register()),
        (34, SuperHRegister::Y1.register()),
        (40, SuperHRegister::Mod.register()),
        (41, SuperHRegister::Ssr.register()),
        (42, SuperHRegister::Spc.register()),
        (43, SuperHRegister::Rs.register()),
        (44, SuperHRegister::Re.register()),
        (51, SuperHRegister::R0b.register()),
        (52, SuperHRegister::R1b.register()),
        (53, SuperHRegister::R2b.register()),
        (54, SuperHRegister::R3b.register()),
        (55, SuperHRegister::R4b.register()),
        (56, SuperHRegister::R5b.register()),
        (57, SuperHRegister::R6b.register()),
        (58, SuperHRegister::R7b.register()),
    ]);
}

#[gdb_target_description]
#[derive(Debug, Default)]
pub struct ShDescription {
    #[args(
        gdb_arch_name("sh"),
        gdb_feature_xml(SH1),
        register_map(SH_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::SuperH(SuperHRegister::Pc))),
        endianness(ArchEndian::BigEndian)
    )]
    args: PhantomData<()>,
}
#[gdb_target_description]
#[derive(Debug, Default)]
pub struct ShDspDescription {
    #[args(
        gdb_arch_name("sh-dsp"),
        gdb_feature_xml(SH1_DSP),
        register_map(SH_DSP_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::SuperH(SuperHRegister::Pc))),
        endianness(ArchEndian::BigEndian)
    )]
    args: PhantomData<()>,
}
#[gdb_target_description]
#[derive(Debug, Default)]
pub struct Sh2Description {
    #[args(
        gdb_arch_name("sh2"),
        gdb_feature_xml(SH2),
        register_map(SH2_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::SuperH(SuperHRegister::Pc))),
        endianness(ArchEndian::BigEndian)
    )]
    args: PhantomData<()>,
}
#[gdb_target_description]
#[derive(Debug, Default)]
pub struct Sh2ADescription {
    #[args(
        gdb_arch_name("sh2a"),
        gdb_feature_xml(SH2A),
        register_map(SH2A_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::SuperH(SuperHRegister::Pc))),
        endianness(ArchEndian::BigEndian)
    )]
    args: PhantomData<()>,
}
#[gdb_target_description]
#[derive(Debug, Default)]
pub struct Sh2ANoFpuDescription {
    #[args(
        gdb_arch_name("sh2a-nofpu"),
        gdb_feature_xml(SH2A_NOFPU),
        register_map(SH2A_NOFPU_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::SuperH(SuperHRegister::Pc))),
        endianness(ArchEndian::BigEndian)
    )]
    args: PhantomData<()>,
}
#[gdb_target_description]
#[derive(Debug, Default)]
pub struct Sh2EDescription {
    #[args(
        gdb_arch_name("sh2e"),
        gdb_feature_xml(SH2E),
        register_map(SH2E_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::SuperH(SuperHRegister::Pc))),
        endianness(ArchEndian::BigEndian)
    )]
    args: PhantomData<()>,
}
#[gdb_target_description]
#[derive(Debug, Default)]
pub struct Sh3Description {
    #[args(
        gdb_arch_name("sh3"),
        gdb_feature_xml(SH3),
        register_map(SH3_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::SuperH(SuperHRegister::Pc))),
        endianness(ArchEndian::BigEndian)
    )]
    args: PhantomData<()>,
}
#[gdb_target_description]
#[derive(Debug, Default)]
pub struct Sh3EDescription {
    #[args(
        gdb_arch_name("sh3e"),
        gdb_feature_xml(SH3E),
        register_map(SH3E_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::SuperH(SuperHRegister::Pc))),
        endianness(ArchEndian::BigEndian)
    )]
    args: PhantomData<()>,
}
#[gdb_target_description]
#[derive(Debug, Default)]
pub struct Sh3DspDescription {
    #[args(
        gdb_arch_name("sh3-dsp"),
        gdb_feature_xml(SH3_DSP),
        register_map(SH3_DSP_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::SuperH(SuperHRegister::Pc))),
        endianness(ArchEndian::BigEndian)
    )]
    args: PhantomData<()>,
}
#[gdb_target_description]
#[derive(Debug, Default)]
pub struct Sh4Description {
    #[args(
        gdb_arch_name("sh4"),
        gdb_feature_xml(SH4),
        register_map(SH4_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::SuperH(SuperHRegister::Pc))),
        endianness(ArchEndian::BigEndian)
    )]
    args: PhantomData<()>,
}
#[gdb_target_description]
#[derive(Debug, Default)]
pub struct Sh4NoFpuDescription {
    #[args(
        gdb_arch_name("sh4-nofpu"),
        gdb_feature_xml(SH4_NOFPU),
        register_map(SH4_NOFPU_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::SuperH(SuperHRegister::Pc))),
        endianness(ArchEndian::BigEndian)
    )]
    args: PhantomData<()>,
}
#[gdb_target_description]
#[derive(Debug, Default)]
pub struct Sh4ADescription {
    #[args(
        gdb_arch_name("sh4a"),
        gdb_feature_xml(SH4A),
        register_map(SH4A_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::SuperH(SuperHRegister::Pc))),
        endianness(ArchEndian::BigEndian)
    )]
    args: PhantomData<()>,
}
#[gdb_target_description]
#[derive(Debug, Default)]
pub struct Sh4ANoFpuDescription {
    #[args(
        gdb_arch_name("sh4a-nofpu"),
        gdb_feature_xml(SH4A_NOFPU),
        register_map(SH4A_NOFPU_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::SuperH(SuperHRegister::Pc))),
        endianness(ArchEndian::BigEndian)
    )]
    args: PhantomData<()>,
}

#[gdb_target_description]
#[derive(Debug, Default)]
pub struct Sh4ALDspDescription {
    #[args(
        gdb_arch_name("sh4al-dsp"),
        gdb_feature_xml(SH4AL_DSP),
        register_map(SH4AL_DSP_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::SuperH(SuperHRegister::Pc))),
        endianness(ArchEndian::BigEndian)
    )]
    args: PhantomData<()>,
}
