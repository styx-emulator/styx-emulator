// SPDX-License-Identifier: BSD-2-Clause

use styx_pcode_translator::sla;

use crate::arch_spec::ArchSpecBuilder;
use crate::PcodeBackend;

pub fn build() -> ArchSpecBuilder<sla::Blackfin, PcodeBackend> {
    let mut spec = ArchSpecBuilder::default();

    super::blackfin_common(&mut spec);

    spec
}
