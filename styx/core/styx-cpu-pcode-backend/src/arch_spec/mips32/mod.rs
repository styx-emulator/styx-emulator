// SPDX-License-Identifier: BSD-2-Clause

use styx_cpu_type::arch::backends::ArchVariant;
use styx_cpu_type::ArchEndian;
use styx_errors::anyhow::anyhow;
use styx_errors::UnknownError;
use styx_pcode_translator::sla::{Mips32be, Mips32le};

use crate::arch_spec::{mips_common, ArchSpec};
use crate::PcodeBackend;

pub fn build_mips32le() -> super::ArchSpecBuilder<Mips32le, PcodeBackend> {
    let mut spec = super::ArchSpecBuilder::default();
    mips_common::mips_common(&mut spec);
    spec
}
pub fn build_mips32be() -> super::ArchSpecBuilder<Mips32be, PcodeBackend> {
    let mut spec = super::ArchSpecBuilder::default();
    mips_common::mips_common(&mut spec);
    spec
}

pub fn mips32_arch_spec(
    arch: &ArchVariant,
    endian: ArchEndian,
) -> Result<ArchSpec<PcodeBackend>, UnknownError> {
    Ok(match arch {
        ArchVariant::Mips32(_variant) => match endian {
            ArchEndian::LittleEndian => build_mips32le().build(arch),
            ArchEndian::BigEndian => build_mips32be().build(arch),
        },
        _ => return Err(anyhow!("bad architecture {arch:?} in mips32 arch spec")),
    })
}
