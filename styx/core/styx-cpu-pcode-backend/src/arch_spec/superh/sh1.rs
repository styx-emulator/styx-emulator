// SPDX-License-Identifier: BSD-2-Clause

use crate::arch_spec::ArchSpecBuilder;
use styx_pcode_translator::{sla, sla::Sh1UserOps};

pub fn build() -> ArchSpecBuilder<sla::Sh1> {
    let mut spec = ArchSpecBuilder::default();

    spec.set_pc_manager(super::StandardPcManager::default().into());
    spec.set_generator(super::StandardGeneratorHelper.into());

    spec.call_other_manager
        .add_handler(Sh1UserOps::SleepStandby, super::call_other::SleepStandby)
        .unwrap();

    spec
}
