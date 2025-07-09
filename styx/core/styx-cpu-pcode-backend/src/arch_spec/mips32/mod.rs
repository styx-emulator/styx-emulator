// SPDX-License-Identifier: BSD-2-Clause

use crate::arch_spec::{mips_common, ArchSpec};
use styx_cpu_type::{arch::backends::ArchVariant, ArchEndian};
use styx_errors::{anyhow::anyhow, UnknownError};
use styx_pcode_translator::sla::{Mips32be, Mips32le};

pub fn build_mips32le() -> super::ArchSpecBuilder<Mips32le> {
    let mut spec = super::ArchSpecBuilder::default();
    mips_common::mips_common(&mut spec);
    spec
}
pub fn build_mips32be() -> super::ArchSpecBuilder<Mips32be> {
    let mut spec = super::ArchSpecBuilder::default();
    mips_common::mips_common(&mut spec);
    spec
}

pub fn mips32_arch_spec(arch: &ArchVariant, endian: ArchEndian) -> Result<ArchSpec, UnknownError> {
    Ok(match arch {
        ArchVariant::Mips32(_variant) => match endian {
            ArchEndian::LittleEndian => build_mips32le().build(arch),
            ArchEndian::BigEndian => build_mips32be().build(arch),
        },
        _ => return Err(anyhow!("bad architecture {arch:?} in mips32 arch spec")),
    })
}
