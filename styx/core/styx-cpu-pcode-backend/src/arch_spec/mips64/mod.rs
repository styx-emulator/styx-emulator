// SPDX-License-Identifier: BSD-2-Clause

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
