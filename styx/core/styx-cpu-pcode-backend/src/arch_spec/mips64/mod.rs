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

use styx_cpu_type::{arch::backends::ArchVariant, ArchEndian};
use styx_errors::{anyhow::anyhow, UnknownError};
use styx_pcode_translator::sla::{Mips64be, Mips64le};

use crate::{arch_spec::mips_common::mips_common, arch_spec::ArchSpec};

pub fn build_mips64le() -> super::ArchSpecBuilder<Mips64le> {
    let mut spec = super::ArchSpecBuilder::default();
    mips_common(&mut spec);
    spec
}
pub fn build_mips64be() -> super::ArchSpecBuilder<Mips64be> {
    let mut spec = super::ArchSpecBuilder::default();
    mips_common(&mut spec);
    spec
}

pub fn mips64_arch_spec(arch: &ArchVariant, endian: ArchEndian) -> Result<ArchSpec, UnknownError> {
    Ok(match arch {
        ArchVariant::Mips64(_variant) => match endian {
            ArchEndian::LittleEndian => build_mips64le().build(arch),
            ArchEndian::BigEndian => build_mips64be().build(arch),
        },
        _ => return Err(anyhow!("bad architecture {arch:?} in mips arch spec")),
    })
}
