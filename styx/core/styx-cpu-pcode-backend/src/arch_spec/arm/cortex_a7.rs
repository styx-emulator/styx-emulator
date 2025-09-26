// SPDX-License-Identifier: BSD-2-Clause

use std::str::FromStr;

use crate::{
    arch_spec::{
        arm::{armv7_common, armv7a_common},
        ArchSpecBuilder,
    },
    PcodeBackend,
};
use styx_pcode::sla::SlaUserOps;
use styx_pcode_translator::sla::{Arm7Be, Arm7Le};

pub fn build_le() -> ArchSpecBuilder<Arm7Le, PcodeBackend> {
    build()
}

pub fn build_be() -> ArchSpecBuilder<Arm7Be, PcodeBackend> {
    build()
}

pub fn build<S: SlaUserOps<UserOps: FromStr>>() -> ArchSpecBuilder<S, PcodeBackend> {
    let mut spec = ArchSpecBuilder::default();

    spec.set_pc_manager(super::StandardPcManager::default().into());

    spec.set_generator(super::StandardGeneratorHelper::default().into());

    armv7_common(&mut spec);

    armv7a_common(&mut spec);

    spec
}
