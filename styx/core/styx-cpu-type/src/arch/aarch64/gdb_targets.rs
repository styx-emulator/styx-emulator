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
use std::{collections::BTreeMap, marker::PhantomData};

use crate::arch::{
    backends::{ArchRegister, BasicArchRegister},
    CpuRegister,
};

use super::Aarch64Register;
use styx_macros::gdb_target_description;
use styx_sync::lazy_static;
use styx_util::gdb_xml::AARCH64_CORE;

lazy_static! {
    /// # lazy-static
    /// This is allowed to be a static since this is a compile-time
    /// derived static that holds constant data
    pub static ref AARCH64_CORE_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
        (0, Aarch64Register::X0.register()),
        (1, Aarch64Register::X1.register()),
        (2, Aarch64Register::X2.register()),
        (3, Aarch64Register::X3.register()),
        (4, Aarch64Register::X4.register()),
        (5, Aarch64Register::X5.register()),
        (6, Aarch64Register::X6.register()),
        (7, Aarch64Register::X7.register()),
        (8, Aarch64Register::X8.register()),
        (9, Aarch64Register::X9.register()),
        (10, Aarch64Register::X10.register()),
        (11, Aarch64Register::X11.register()),
        (12, Aarch64Register::X12.register()),
        (13, Aarch64Register::X13.register()),
        (14, Aarch64Register::X14.register()),
        (15, Aarch64Register::X15.register()),
        (16, Aarch64Register::X16.register()),
        (17, Aarch64Register::X17.register()),
        (18, Aarch64Register::X18.register()),
        (19, Aarch64Register::X19.register()),
        (20, Aarch64Register::X20.register()),
        (21, Aarch64Register::X21.register()),
        (22, Aarch64Register::X22.register()),
        (23, Aarch64Register::X23.register()),
        (24, Aarch64Register::X24.register()),
        (25, Aarch64Register::X25.register()),
        (26, Aarch64Register::X26.register()),
        (27, Aarch64Register::X27.register()),
        (28, Aarch64Register::X28.register()),
        (29, Aarch64Register::X29.register()),
        (30, Aarch64Register::X30.register()),
        (31, Aarch64Register::SP.register()),
        (32, Aarch64Register::PC.register()),
        (33, Aarch64Register::Cpsr.register()),
    ]);
}

#[gdb_target_description]
#[derive(Debug, Default)]
pub struct Aarch64CoreDescription {
    #[args(
        gdb_arch_name("aarch64"),
        gdb_feature_xml(AARCH64_CORE),
        register_map(AARCH64_CORE_REGISTER_MAP),
        pc_register(ArchRegister::Basic(BasicArchRegister::Aarch64(Aarch64Register::PC))),
        endianness(ArchEndian::LittleEndian)
    )]
    args: PhantomData<()>,
}
