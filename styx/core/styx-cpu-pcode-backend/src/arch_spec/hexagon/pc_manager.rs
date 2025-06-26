use log::trace;
use styx_cpu_type::arch::hexagon::HexagonRegister;

use crate::{
    arch_spec::{pc_manager::PcOverflow, ArchPcManager},
    memory::sized_value::SizedValue,
    register_manager::RegisterManager,
    PcodeBackend, SharedStateKey,
};

#[derive(Debug, Default)]
pub struct StandardPcManager {
    isa_pc: u64,
    internal_pc: u64,
    new_internal_pc: u64,
    in_duplex: bool,
    // default is false
    internal_pc_set_during_packet: bool,
    initial_internal_pc_set: bool,
}

// TODO: we need to have this advance the PC
// at the end of every packet
impl ArchPcManager for StandardPcManager {
    fn isa_pc(&self) -> u64 {
        trace!("getting isa pc {}", self.isa_pc);
        self.isa_pc
    }

    fn set_isa_pc(&mut self, value: u64, backend: &mut PcodeBackend) {
        trace!("setting isa pc to {}", value);
        self.isa_pc = value;
        // TODO: fix this
        let _ = RegisterManager::write_register(
            backend,
            HexagonRegister::Pc.into(),
            SizedValue::from(self.isa_pc as u32),
        );
    }
    fn pre_fetch(&mut self, _backend: &mut PcodeBackend) -> Result<(), PcOverflow> {
        self.internal_pc_set_during_packet = false;
        Ok(())
    }

    fn internal_pc(&self) -> u64 {
        self.internal_pc
    }

    fn set_internal_pc(&mut self, value: u64, backend: &mut PcodeBackend) {
        // Since set_internal_pc is only ever called from
        // instructions that have absolute branching, or set_pc (which is called from write_register_raw)
        // we can always set the ISA pc here.
        //
        // write_register_raw is from context restore
        //
        // NOTE: in the case of a branch, this is called BEFORE post_execute.
        // TODO: relative branching? does that even matter?
        // NOTE: this may at times set the internal PC in RegisterManager twice (if called from set_pc), but that's fine
        // NOTE: if we make the assumption that set_internal_pc can be called at any point in the fetch/decode/execute_cycle, then
        // we should just set isa_pc_set_this_cycle to true.

        // write out the registers
        if !self.initial_internal_pc_set {
            self.initial_internal_pc_set = true;

            self.internal_pc = value;
            self.set_isa_pc(self.internal_pc, backend);
        } else {
            self.new_internal_pc = value;
            self.internal_pc_set_during_packet = true;
        }
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

        self.internal_pc = self.internal_pc + bytes_consumed;

        // The ISA PC increments in packet granularity.
        // Get the start of the packet. If the start of the packet is the same
        // as current ISA PC, then we're still in this packet.
        // If it has changed, we are in the next packet.
        //
        // We check branch since if set_internal_pc was called before this, a branch happened,
        // and so we don't care about the next sequential packet start.
        if !self.internal_pc_set_during_packet {
            match backend.shared_state.get(&SharedStateKey::HexagonPktStart) {
                // New packet, no branching or anything
                Some(new_pkt_start)
                    if self.isa_pc as u128 != *new_pkt_start
                        && !self.internal_pc_set_during_packet =>
                {
                    trace!("new packet, setting ISA PC to {}", new_pkt_start);
                    self.set_isa_pc(*new_pkt_start as u64, backend);
                }
                // This is the case where the internal PC was set earlier in the cycle
                // (indicative of branching) but we don't want to set it until the end of the packet.
                Some(new_pkt_start)
                    if self.isa_pc as u128 != *new_pkt_start
                        && self.internal_pc_set_during_packet =>
                {
                    trace!(
                        "new but internal ISA set during packet cycle, setting ISA PC to {}",
                        new_pkt_start
                    );
                    self.internal_pc = self.new_internal_pc;
                    self.set_isa_pc(self.internal_pc as u64, backend);
                }
                Some(new_pkt_start) => {
                    trace!(
                        "value of ISA PC {}, shared state pkt start {}",
                        self.isa_pc,
                        new_pkt_start
                    );
                }
                _ => {}
            }
        }

        Ok(())
    }
}
