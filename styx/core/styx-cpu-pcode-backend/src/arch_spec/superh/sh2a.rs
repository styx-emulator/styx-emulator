// SPDX-License-Identifier: BSD-2-Clause

use std::str::FromStr;

use crate::arch_spec::ArchSpecBuilder;
use styx_cpu_type::arch::superh::SuperHRegister;
use styx_pcode_translator::sla::{self, Sh2aUserOps};

use crate::arch_spec::superh::register::*;

pub fn build() -> ArchSpecBuilder<sla::Sh2a> {
    let mut spec = ArchSpecBuilder::default();

    spec.set_pc_manager(super::StandardPcManager::default().into());
    spec.set_generator(super::StandardGeneratorHelper.into());

    spec.call_other_manager
        .add_handler(Sh2aUserOps::SleepStandby, super::call_other::SleepStandby)
        .unwrap();

    // floating point registers
    for x in 0..15 {
        let reg = SuperHRegister::from_str(&format!("Fr{x}")).unwrap();
        spec.register_manager
            .add_handler(reg, FloatingPointExtensionHandler::default())
            .unwrap();
    }
    spec.register_manager
        .add_handler(
            SuperHRegister::Fpscr,
            FloatingPointExtensionHandler::default(),
        )
        .unwrap();

    spec
}
