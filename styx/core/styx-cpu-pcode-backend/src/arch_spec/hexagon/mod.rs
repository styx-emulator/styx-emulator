// SPDX-License-Identifier: BSD-2-Clause
use super::generator_helper::EmptyGeneratorHelper;
use super::ArchSpecBuilder;
use super::GeneratorHelper;
use super::HexagonPcodeBackend;

pub mod backend;
// Anything related to packet semantics
mod dotnew;
mod pkt_semantics;
mod regpairs;

mod system;

#[cfg(test)]
pub mod tests;

use pkt_semantics::NewReg;
use styx_pcode_translator::sla::{self, HexagonUserOps};

fn parse_iclass(insn: u32) -> u32 {
    (insn >> 28) & 0xf
}

// Adapted from PPC
pub fn build() -> ArchSpecBuilder<sla::Hexagon, HexagonPcodeBackend> {
    let mut spec = ArchSpecBuilder::default();

    // Generator + pc manager. For now use the default pc manager
    spec.set_generator(GeneratorHelper::Empty(EmptyGeneratorHelper::default()));

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Newreg, NewReg {})
        .unwrap();

    system::tlb::add_tlb_callothers(&mut spec);
    system::icache::add_icache_callothers(&mut spec);
    system::dcache::add_dcache_callothers(&mut spec);
    system::l2::add_l2_callothers(&mut spec);
    system::interrupt::add_interrupt_callothers(&mut spec);

    regpairs::add_vector_register_pair_handlers(&mut spec);

    spec
}
