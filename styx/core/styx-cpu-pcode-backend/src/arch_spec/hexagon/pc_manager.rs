use log::trace;

use crate::{
    arch_spec::{pc_manager::PcOverflow, ArchPcManager},
    PcodeBackend,
};

#[derive(Debug, Default)]
pub struct StandardPcManager {
    isa_pc: u64,
    internal_pc: u64,
    in_duplex: bool,
    pkt_start: u64,
}

// TODO: we need to have this advance the PC
// at the end of every packet
impl ArchPcManager for StandardPcManager {
    fn isa_pc(&self) -> u64 {
        self.isa_pc
    }

    fn set_isa_pc(&mut self, value: u64, backend: &mut PcodeBackend) {
        self.isa_pc = value
    }

    fn internal_pc(&self) -> u64 {
        self.internal_pc
    }

    fn set_internal_pc(&mut self, value: u64, _backend: &mut PcodeBackend) {
        self.internal_pc = value;
    }

    fn post_execute(
        &mut self,
        bytes_consumed: u64,
        backend: &mut PcodeBackend,
    ) -> Result<(), PcOverflow> {
        // Update duplex
        self.in_duplex = !self.in_duplex && bytes_consumed == 2;

        trace!(
            "instruction at {} consumed {} bytes in_duplex {}",
            self.internal_pc,
            bytes_consumed,
            self.in_duplex
        );

        // TODO: I think the generator helper needs to set some context
        // regs for pkt_start and pkt_end -- could we just acquire these instead?
        self.set_internal_pc(self.internal_pc + bytes_consumed, backend);

        // TODO: here, obtain the mmu, obtain the instruction,
        // if it's the end of the packet, advance the isa pc

        Ok(())
    }
}
