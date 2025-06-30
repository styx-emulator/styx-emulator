use super::ArchSpecBuilder;
use super::GeneratorHelper;
use super::PcManager;

mod helpers;
mod pc_manager;
// Anything related to packet semantics
mod pkt_semantics;

#[cfg(test)]
pub mod tests;

pub use helpers::HexagonGeneratorHelper;
pub use pc_manager::StandardPcManager;

use pkt_semantics::NewReg;
use styx_pcode::sla::SlaUserOps;
use styx_pcode_translator::sla::{self, HexagonUserOps};

// Adapted from PPC
pub fn build() -> ArchSpecBuilder<sla::Hexagon> {
    let mut spec = ArchSpecBuilder::default();

    // Generator + pc manager. For now use the default pc manager
    spec.set_generator(GeneratorHelper::Hexagon(HexagonGeneratorHelper::default()));
    spec.set_pc_manager(PcManager::Hexagon(StandardPcManager::default()));

    // TODO: callother manager for system instructions, reg manager

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Newreg, NewReg {})
        .unwrap();

    spec
}
