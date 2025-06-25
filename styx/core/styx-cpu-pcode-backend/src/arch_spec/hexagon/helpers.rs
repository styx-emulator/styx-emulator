use std::collections::HashMap;

use crate::arch_spec::generator_helper::CONTEXT_OPTION_LEN;
use crate::PcodeBackend;
use crate::{arch_spec::GeneratorHelp, pcode_gen::GeneratePcodeError};
use log::{debug, error, trace, warn};
use smallvec::{smallvec, SmallVec};
use styx_errors::UnknownError;
use styx_pcode::pcode::{SpaceName, VarnodeData};
use styx_pcode_translator::ContextOption;
use styx_processor::{cpu::CpuBackend, memory::Mmu};

// How many insns to fetch to analyze for duplexes?
// Is trapping easier?
// this will be used later if there are performance issues with the current solution
// const PREFETCH_SIZE: u16 = 10;

#[derive(Copy, Clone, Debug)]
enum DuplexInsClass {
    A = 1,
    L1 = 2,
    L2 = 3,
    S1 = 4,
    S2 = 5,
}

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
enum PktLoopParseBits {
    Duplex = 0,
    NotEndOfPacket1 = 1,
    NotEndOfPacket2 = 2,
    EndOfPacket = 3,
    Other,
}

impl From<u32> for PktLoopParseBits {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::Duplex,
            1 => Self::NotEndOfPacket1,
            2 => Self::NotEndOfPacket2,
            3 => Self::EndOfPacket,
            _ => Self::Other,
        }
    }
}

#[derive(Debug)]
pub struct HexagonGeneratorHelper {
    // map code address -> subinsn type
    subinsn_map: HashMap<u64, u32>,
    pc_varnode: VarnodeData,
    pkt_end: u64,
    // Stores if the last instruction was the end of a packet.
    last_pkt_ended: bool,
    set_immext: bool,
}

impl Default for HexagonGeneratorHelper {
    fn default() -> Self {
        Self {
            subinsn_map: Default::default(),
            // TODO: will this actually work with virtual memory and such,
            // or do I need to perform a page table lookup?
            pc_varnode: VarnodeData {
                space: SpaceName::Ram,
                offset: 0,
                size: 4,
            },
            pkt_end: 0,
            last_pkt_ended: true,
            // Presumably this needs to be set once, and never again.
            // TODO: make sure this is true by trying an instruction that would actually use an immext
            set_immext: true,
        }
    }
}

impl GeneratorHelp for HexagonGeneratorHelper {
    fn pre_fetch(
        &mut self,
        backend: &mut PcodeBackend,
        mmu: &mut Mmu,
    ) -> Result<SmallVec<[ContextOption; CONTEXT_OPTION_LEN]>, GeneratePcodeError> {
        // Read where the PC's at and then figure out what the next 2 subinsn values should be.
        // Check our lut here first

        let mut context_opts: SmallVec<[ContextOption; 4]> = SmallVec::new();

        if self.set_immext {
            self.set_immext = false;
            context_opts.push(ContextOption::HexagonImmext(0xffffffff));
        }

        // Save this off
        let last_pkt_ended = self.last_pkt_ended;
        self.last_pkt_ended = true;

        match backend.pc() {
            Ok(unwrapped_pc) => {
                self.pc_varnode.offset = unwrapped_pc;

                if let Some(subinsn_type) = self.subinsn_map.get(&self.pc_varnode.offset) {
                    context_opts.push(ContextOption::HexagonSubinsn(*subinsn_type));
                } else {
                    // The hashmap doesn't have anything for us anymore, we
                    // need to repopulate
                    self.subinsn_map.clear();

                    // Is there a performance impact of hitting the MMU?
                    match mmu.read_u32_le_virt_code(self.pc_varnode.offset) {
                        Ok(insn_data) => {
                            // bytes we want: 31|30|29|14

                            trace!("insn data is 0x{:x}", insn_data);
                            let pkt_type: PktLoopParseBits = ((insn_data >> 14) & 0b11).into();
                            match pkt_type {
                                PktLoopParseBits::Duplex => {
                                    let insclass =
                                        ((insn_data >> 28) & 0b1110) | ((insn_data >> 13) & 0b1);
                                    trace!("duplex instruction, insclass {}", insclass);
                                    // From https://github.com/toshipiazza/ghidra-plugin-hexagon/blob/main/Ghidra/Processors/Hexagon/src/main/java/ghidra/app/plugin/core/analysis/HexagonInstructionInfo.java#L68
                                    let duplex_slots = match insclass {
                                        0 => (DuplexInsClass::L1, DuplexInsClass::L1),
                                        1 => (DuplexInsClass::L2, DuplexInsClass::L1),
                                        2 => (DuplexInsClass::L2, DuplexInsClass::L2),
                                        3 => (DuplexInsClass::A, DuplexInsClass::A),
                                        4 => (DuplexInsClass::L1, DuplexInsClass::A),
                                        5 => (DuplexInsClass::L2, DuplexInsClass::A),
                                        6 => (DuplexInsClass::S1, DuplexInsClass::A),
                                        7 => (DuplexInsClass::S2, DuplexInsClass::A),
                                        8 => (DuplexInsClass::S1, DuplexInsClass::L1),
                                        9 => (DuplexInsClass::S1, DuplexInsClass::L2),
                                        10 => (DuplexInsClass::S1, DuplexInsClass::S1),
                                        11 => (DuplexInsClass::S2, DuplexInsClass::S1),
                                        12 => (DuplexInsClass::S2, DuplexInsClass::L1),
                                        13 => (DuplexInsClass::S2, DuplexInsClass::L2),
                                        14 => (DuplexInsClass::S2, DuplexInsClass::S2),
                                        // Realistically, this should be some sort of bad instruction thing
                                        _ => unreachable!(),
                                    };

                                    // TODO: why use a hashmap? it may make it easier to implement
                                    // larger blocks of prefetches in the future.
                                    // If the performance impact is negligible, just switch to a
                                    // next_subinsn_class variable
                                    //
                                    // Also, maybe saving the current pc might be useful if some exception
                                    // occurs
                                    self.subinsn_map.insert(unwrapped_pc, duplex_slots.0 as u32);
                                    // TODO: overflow checks?
                                    self.subinsn_map
                                        .insert(unwrapped_pc + 2, duplex_slots.1 as u32);

                                    trace!("duplex slot 1 slot 2 subinsn type {:?}", duplex_slots);

                                    // First insn in duplex is a pkt start
                                    context_opts
                                        .push(ContextOption::HexagonSubinsn(duplex_slots.0 as u32));
                                    context_opts
                                        .push(ContextOption::HexagonPktStart(unwrapped_pc as u32));
                                }
                                // The start of a new packet
                                // Based on: https://github.com/toshipiazza/ghidra-plugin-hexagon/blob/main/Ghidra/Processors/Hexagon/src/main/java/ghidra/app/plugin/core/analysis/HexagonPacketAnalyzer.java
                                // They also set pkt_next, but pkt_next isn't used in the slaspec (thankfully).
                                PktLoopParseBits::NotEndOfPacket1
                                | PktLoopParseBits::NotEndOfPacket2
                                    if last_pkt_ended =>
                                {
                                    trace!("hexagon start of packet");

                                    // NOTE: there's a truncation here, but since hexagon pointers
                                    // are 32 bits this shouldn't matter?

                                    context_opts
                                        .push(ContextOption::HexagonPktStart(unwrapped_pc as u32));
                                }
                                PktLoopParseBits::NotEndOfPacket1
                                | PktLoopParseBits::NotEndOfPacket2 => {
                                    trace!("hexagon prefetch is middle of packet");
                                }
                                PktLoopParseBits::EndOfPacket => {
                                    self.pkt_end = unwrapped_pc;
                                    self.last_pkt_ended = true;
                                }
                                // TODO
                                PktLoopParseBits::Other => {
                                    error!("shouldn't be here");
                                }
                            }
                        }
                        Err(e) => {
                            warn!(
                                "hexagon couldn't prefetch the next insn for duplex checking: {:?}",
                                e
                            );
                        }
                    }
                }
            }
            Err(e) => {
                warn!("hexagon couldn't obtain current program counter: {:?}", e);
            }
        }

        Ok(context_opts)
    }
}
