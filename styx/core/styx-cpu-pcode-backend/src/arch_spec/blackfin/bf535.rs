// SPDX-License-Identifier: BSD-2-Clause

use styx_pcode_translator::sla;

use crate::arch_spec::ArchSpecBuilder;
use crate::PcodeBackend;

#[allow(dead_code)]
pub fn build() -> ArchSpecBuilder<sla::Blackfin, PcodeBackend> {
    todo!("Implement Blackfin ArchSpecBuilder for BF535")
}
