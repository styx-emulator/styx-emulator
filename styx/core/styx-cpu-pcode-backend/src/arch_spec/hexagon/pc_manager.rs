use log::trace;
use smallvec::SmallVec;
use styx_cpu_type::arch::hexagon::HexagonRegister;

use crate::{
    arch_spec::{pc_manager::PcOverflow, ArchPcManager},
    memory::sized_value::SizedValue,
    register_manager::RegisterManager,
    PcodeBackend, SharedStateKey, DEFAULT_REG_ALLOCATION,
};

#[derive(Debug, Default, Clone)]
pub struct StandardPcManager {
    isa_pc: u64,
    internal_pc: u64,
    new_internal_pc: u64,
    in_duplex: bool,
    // default is false
    internal_pc_set_during_packet: bool,
    last_bytes_consumed: u64,
    // This ignores immext and such
    true_insn_count: usize,
}

impl StandardPcManager {
    fn handle_branching_end_of_packet(&mut self, backend: &mut PcodeBackend) {
        self.internal_pc = self.new_internal_pc;
        self.set_isa_pc(self.internal_pc, backend);
    }
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

    fn internal_pc(&self) -> u64 {
        self.internal_pc
    }

    fn post_fetch(&mut self, bytes_consumed: u64, _backend: &mut PcodeBackend) {
        self.last_bytes_consumed = bytes_consumed;
    }

    fn set_internal_pc(&mut self, value: u64, backend: &mut PcodeBackend, from_branch: bool) {
        // Since set_internal_pc is only ever called from
        // instructions that have absolute branching, or set_pc (which is called from write_register_raw)
        // we can always set the ISA pc here.
        //
        // write_register_raw is from context restore
        //
        // NOTE: in the case of a branch, this is called BEFORE post_execute.
        // TODO: relative branching? does that even matter?
        // NOTE: this may at times set the internal PC in RegisterManager twice (if called from set_pc), but that's fine
        // NOTE: our assumption is that from_branch must be set appropriately for this to work
        // properly.

        // In the case that the PC wasn't set at a branch,
        // we want this to set the ISAPC immediately.
        //
        // In the case where the PC was set at a branch,
        // we want the internal PC to only be set at the end
        // of the packet, thanks to Hexagon pkt semantics.
        if !from_branch {
            self.internal_pc = value;
            self.set_isa_pc(self.internal_pc, backend);
        } else {
            trace!("set_internal_pc called because a branch occurred");

            self.new_internal_pc = value;

            // If this happens at the end of a slot, post_execute will never occur.
            // So we have to handle it again here.
            //
            // If this happens in the middle of a slot, post_execute will also never
            // occur!
            match backend.shared_state.get(&SharedStateKey::HexagonPktStart) {
                Some(new_pkt_start) if self.isa_pc as u128 != *new_pkt_start => {
                    trace!(
                        "LAST instruction in packet was a branch, the next (sequential pkt) is {}, branching to {}",
                        new_pkt_start, self.new_internal_pc
                    );
                    self.handle_branching_end_of_packet(backend)
                }
                // The == is pointless, but for clarity
                Some(new_pkt_start) if self.isa_pc as u128 == *new_pkt_start => {
                    trace!(
                        "middle instruction in packet was a branch, we will deal with it later.",
                    );
                    trace!(
                        "new internal pc {} internal pc set during pkt is {}",
                        self.new_internal_pc,
                        self.internal_pc_set_during_packet
                    );
                    self.internal_pc_set_during_packet = true;
                    self.internal_pc += self.last_bytes_consumed;
                }
                _ => {}
            }
        }
    }

    fn post_execute(
        &mut self,
        bytes_consumed: u64,
        backend: &mut PcodeBackend,
        regs_written: &mut SmallVec<[u64; DEFAULT_REG_ALLOCATION]>,
        total_pcodes: usize,
    ) -> Result<(), PcOverflow> {
        // Update duplex
        self.in_duplex = !self.in_duplex && bytes_consumed == 2;

        trace!(
            "post_execute: regs written {:?} pcodes generated {}",
            regs_written,
            total_pcodes
        );

        trace!(
            "instruction at {} consumed {} bytes in_duplex {} pc set during pkt {} new internal pc {}",
            self.internal_pc,
            bytes_consumed,
            self.in_duplex,
            self.internal_pc_set_during_packet,
            self.new_internal_pc
        );

        // TODO: I think the generator helper needs to set some context
        // regs for pkt_start and pkt_end -- could we just acquire these instead?

        self.internal_pc += bytes_consumed;

        // The ISA PC increments in packet granularity.
        // Get the start of the packet. If the start of the packet is the same
        // as current ISA PC, then we're still in this packet.
        // If it has changed, we are in the next packet.
        //
        // We check branch since if set_internal_pc was called before this, a branch happened,
        // and so we don't care about the next sequential packet start.
        let new_pkt = match backend.shared_state.get(&SharedStateKey::HexagonPktStart) {
            // New packet, no branching or anything
            Some(new_pkt_start)
                if self.isa_pc as u128 != *new_pkt_start && !self.internal_pc_set_during_packet =>
            {
                trace!("new packet, setting ISA PC to {}", new_pkt_start);
                self.set_isa_pc(*new_pkt_start as u64, backend);

                true
            }
            // This is the case where the internal PC was set earlier in the cycle
            // (indicative of branching) but we don't want to set it until the end of the packet.
            Some(new_pkt_start)
                if self.isa_pc as u128 != *new_pkt_start && self.internal_pc_set_during_packet =>
            {
                trace!(
                    "new but internal ISA set during packet cycle, setting ISA PC to {}",
                    self.new_internal_pc
                );

                self.handle_branching_end_of_packet(backend);
                true
            }

            // This is just for logging, a new packet hasn't come yet.
            Some(new_pkt_start) => {
                trace!(
                    "value of ISA PC {}, shared state pkt start {}",
                    self.isa_pc,
                    new_pkt_start
                );
                false
            }
            _ => false,
        };

        if new_pkt {
            trace!("resetting internal pc set during pkt");
            self.internal_pc_set_during_packet = false;
            self.new_internal_pc = 0;
            self.true_insn_count = 0;
        }

        if total_pcodes > 0 {
            trace!("dotnew: inside a real instruction");
            let mut first_general_reg = 0;
            for i in regs_written {
                // TODO: make this more reliable;
                if *i <= 28 * 4 {
                    first_general_reg = *i / 4;
                }
            }
            backend.shared_state.insert(
                SharedStateKey::HexagonInsnRegDest(self.true_insn_count),
                first_general_reg as u128,
            );
            trace!(
                "dotnew: wrote {} -> {}",
                self.true_insn_count,
                first_general_reg
            );
            self.true_insn_count += 1;
            trace!(
                "true instruction count is upped to {}",
                self.true_insn_count
            );
            backend.shared_state.insert(
                SharedStateKey::HexagonTrueInsnCount,
                self.true_insn_count as u128,
            );

            trace!("dotnew: first general reg is {}", first_general_reg);
        }

        Ok(())
    }
}
