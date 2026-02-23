// SPDX-License-Identifier: BSD-2-Clause

use styx_pcode_translator::sla;

use crate::arch_spec::ArchSpecBuilder;
use crate::PcodeBackend;

#[allow(dead_code)] // right now we dont use little endian SH4
pub fn build() -> ArchSpecBuilder<sla::SuperH4Le, PcodeBackend> {
    let mut spec = ArchSpecBuilder::default();

    spec.set_pc_manager(super::StandardPcManager::default().into());
    spec.set_generator(super::StandardGeneratorHelper.into());

    // TODO: floating point register manager?
    // TODO: floating point register conversions?
    // TODO: call others
    spec
}
