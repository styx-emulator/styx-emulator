// SPDX-License-Identifier: BSD-2-Clause

use styx_pcode_translator::sla;
use styx_pcode_translator::sla::Sh2UserOps;

use crate::arch_spec::ArchSpecBuilder;
use crate::PcodeBackend;

pub fn build() -> ArchSpecBuilder<sla::Sh2, PcodeBackend> {
    let mut spec = ArchSpecBuilder::default();

    spec.set_pc_manager(super::StandardPcManager::default().into());
    spec.set_generator(super::StandardGeneratorHelper.into());

    spec.call_other_manager
        .add_handler(Sh2UserOps::SleepStandby, super::call_other::SleepStandby)
        .unwrap();

    spec
}
