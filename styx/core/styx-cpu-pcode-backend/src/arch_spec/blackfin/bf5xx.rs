// SPDX-License-Identifier: BSD-2-Clause

use crate::{arch_spec::ArchSpecBuilder, PcodeBackend};
use styx_pcode_translator::sla;

pub fn build() -> ArchSpecBuilder<sla::Blackfin, PcodeBackend> {
    let mut spec = ArchSpecBuilder::default();

    super::blackfin_common(&mut spec);

    spec
}
