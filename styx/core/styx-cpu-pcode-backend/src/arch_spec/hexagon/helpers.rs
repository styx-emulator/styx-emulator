use crate::arch_spec::generator_helper::CONTEXT_OPTION_LEN;
use crate::{arch_spec::GeneratorHelp, pcode_gen::GeneratePcodeError};
use crate::{PcodeBackend, SharedStateKey};
use log::{error, trace};
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
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

impl PktLoopParseBits {
    fn new_from_insn(insn_data: u32) -> Self {
        ((insn_data >> 14) & 0b11).into()
    }
}

#[derive(Debug)]
enum SubinstructionData {
    EndDuplex(u32),
    EndDuplexEndPacket(u32),
    StartDuplex(u32),
}

#[derive(Debug)]
pub struct HexagonGeneratorHelper {
    // map code address -> subinsn type
    subinsn_map: FxHashMap<u64, SubinstructionData>,
    pc_varnode: VarnodeData,
    pkt_end: u64,
    // Stores if the last instruction was the end of a packet.
    last_pkt_ended: bool,
    duplex_ended: bool,
    first_insn_setup: bool,
    pkt_insns: usize,
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
            first_insn_setup: true,
            pkt_insns: 0,
            duplex_ended: false,
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

        // Save this off
        let last_pkt_ended = self.last_pkt_ended;
        self.last_pkt_ended = true;

        // Get the PC
        match backend.pc() {
            Err(e) => {
                error!("Could not fetch PC from backend: {:?}", e);
                return Err(GeneratePcodeError::InvalidAddress);
            }
            Ok(unwrapped_pc) => {
                self.pc_varnode.offset = unwrapped_pc;

                match self.subinsn_map.get(&self.pc_varnode.offset) {
                    Some(subinsn_data) => {
                        let (duplex_ended, subinsn_type) = match subinsn_data {
                            // Update shared state to the start of the next packet, as is done in the EndPkt case later
                            SubinstructionData::EndDuplexEndPacket(ty) => {
                                trace!("in end duplex that's an end of packet, pushing the next packet and such");

                                self.last_pkt_ended = true;
                                backend.shared_state.insert(
                                    SharedStateKey::HexagonPktStart,
                                    (unwrapped_pc + 2) as u128,
                                );
                                (true, ty)
                            }
                            SubinstructionData::EndDuplex(ty) => (true, ty),
                            SubinstructionData::StartDuplex(ty) => (false, ty),
                        };

                        self.duplex_ended = duplex_ended;

                        context_opts.push(ContextOption::HexagonSubinsn(*subinsn_type));

                        // Consume as we go to prevent a memory leak
                        // by having the map grow infinitely
                        self.subinsn_map.remove(&self.pc_varnode.offset);
                        self.pkt_insns = self.pkt_insns + 1;

                        return Ok(context_opts);
                    }
                    None => {}
                }

                if self.duplex_ended {
                    self.duplex_ended = false;
                    context_opts.push(ContextOption::HexagonSubinsn(0));
                }

                // The hashmap doesn't have anything for us anymore, we
                // need to repopulate
                self.subinsn_map.clear();

                // Is there a performance impact of hitting the MMU?
                // Now we fetch four instructions!
                match mmu.read_u128_le_virt_code(self.pc_varnode.offset) {
                    Err(e) => {
                        error!(
                            "couldn't prefetch the next insn for duplex checking from MMU: {:?}",
                            e
                        );
                        return Err(GeneratePcodeError::InvalidAddress);
                    }
                    Ok(insn_data_wide) => {
                        // bits we want: 31|30|29|14

                        // There was no need to mask, but clarity
                        let insn_data = (insn_data_wide & 0xffffffff) as u32;
                        let insn_next = ((insn_data_wide >> 32) & 0xffffffff) as u32;
                        let insn_next1 = ((insn_data_wide >> 64) & 0xffffffff) as u32;
                        let insn_next2 = ((insn_data_wide >> 96) & 0xffffffff) as u32;
                        let parse_next = PktLoopParseBits::new_from_insn(insn_next);
                        let parse_next1 = PktLoopParseBits::new_from_insn(insn_next1);
                        let parse_next2 = PktLoopParseBits::new_from_insn(insn_next2);

                        trace!("insn data is 0x{:x}", insn_data);

                        let pkt_type = PktLoopParseBits::new_from_insn(insn_data);
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
                                // TODO: overflow checks?

                                trace!("duplex slot 1 slot 2 subinsn type {:?}", duplex_slots);

                                // First insn in duplex is a pkt start
                                context_opts
                                    .push(ContextOption::HexagonSubinsn(duplex_slots.0 as u32));

                                if self.first_insn_setup {
                                    self.first_insn_setup = false;

                                    // If standalone, this should be EndDuplexEndPacket

                                    // D I Ie or D Ie
                                    if (parse_next == PktLoopParseBits::EndOfPacket
                                        || ((parse_next == PktLoopParseBits::NotEndOfPacket1
                                            || parse_next == PktLoopParseBits::NotEndOfPacket2)
                                            && parse_next2 == PktLoopParseBits::EndOfPacket))
                                    {
                                        self.subinsn_map.insert(
                                            unwrapped_pc + 2,
                                            SubinstructionData::EndDuplex(duplex_slots.1 as u32),
                                        );
                                    }
                                    // Standalone
                                    else {
                                        self.subinsn_map.insert(
                                            unwrapped_pc + 2,
                                            SubinstructionData::EndDuplexEndPacket(
                                                duplex_slots.1 as u32,
                                            ),
                                        );
                                    }

                                    context_opts
                                        .push(ContextOption::HexagonPktStart(unwrapped_pc as u32));
                                }
                                // If not, we should inspect the following insns to figure out whether this duplex is at the end of the packet
                                // Duplex comes in these combos:
                                // Ie = end
                                // I I D |
                                // I D Ie |
                                // D I Ie |
                                //
                                // D
                                //
                                // I D
                                // D Iend
                                else if self.pkt_insns <= 1 &&
                                // D I (end) or I D I (end)
                                (parse_next == PktLoopParseBits::EndOfPacket ||
                                        // D I I (end)
                                         ( (parse_next == PktLoopParseBits::NotEndOfPacket1 || parse_next == PktLoopParseBits::NotEndOfPacket2)
                                              && parse_next2 == PktLoopParseBits::EndOfPacket))
                                {
                                    trace!(
                                        "this duplex instruction pair does not terminate a packet"
                                    );
                                    self.subinsn_map.insert(
                                        unwrapped_pc + 2,
                                        SubinstructionData::EndDuplex(duplex_slots.1 as u32),
                                    );
                                    // Start of packet
                                    if self.last_pkt_ended {
                                        self.pkt_insns = 0;
                                    }
                                }
                                // Emit pkt start if we are in IID, D, or ID scenario (should be EndDuplexEndPacket)
                                // Remaining case is I I D or I D
                                else {
                                    trace!("this duplex instruction pair DOES terminate a packet");
                                    self.subinsn_map.insert(
                                        unwrapped_pc + 2,
                                        SubinstructionData::EndDuplexEndPacket(
                                            duplex_slots.1 as u32,
                                        ),
                                    );
                                }
                            }
                            // First instruction in the won't have anything taken care of
                            PktLoopParseBits::NotEndOfPacket1
                            | PktLoopParseBits::NotEndOfPacket2
                                if self.first_insn_setup =>
                            {
                                trace!(
                                    "First instruction helper has seen, setting up context opts"
                                );
                                self.first_insn_setup = false;

                                context_opts.push(ContextOption::HexagonImmext(0xffffffff));
                                context_opts
                                    .push(ContextOption::HexagonPktStart(unwrapped_pc as u32));

                                backend
                                    .shared_state
                                    .insert(SharedStateKey::HexagonPktStart, unwrapped_pc as u128);
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

                                // In case of branching, we need to do a quick sanity check
                                // to make sure that value in our shared state matches, otherwise
                                // we need to update it here.
                                match backend.shared_state.get(&SharedStateKey::HexagonPktStart) {
                                    Some(next_pkt_start)
                                        if *next_pkt_start != unwrapped_pc as u128 =>
                                    {
                                        trace!("helper detected a branch, updating shared state for consistency");
                                        backend.shared_state.insert(
                                            SharedStateKey::HexagonPktStart,
                                            unwrapped_pc as u128,
                                        );
                                    }
                                    _ => {}
                                }

                                context_opts
                                    .push(ContextOption::HexagonPktStart(unwrapped_pc as u32));

                                self.last_pkt_ended = false;
                                self.pkt_insns = 0;
                            }
                            PktLoopParseBits::NotEndOfPacket1
                            | PktLoopParseBits::NotEndOfPacket2 => {
                                trace!("hexagon prefetch is middle of packet");
                            }
                            PktLoopParseBits::EndOfPacket => {
                                self.pkt_end = unwrapped_pc;
                                self.last_pkt_ended = true;
                                trace!("got to end of pkt");

                                // Not a duplex, so next ins is +4 away in packet distance
                                backend.shared_state.insert(
                                    SharedStateKey::HexagonPktStart,
                                    (unwrapped_pc + 4) as u128,
                                );

                                // Special care is taken for an end of packet
                                // that is the first packet seen
                                if self.first_insn_setup {
                                    trace!(
                                        "First instruction helper but the packet has only 1 insn"
                                    );

                                    self.first_insn_setup = false;

                                    context_opts.push(ContextOption::HexagonImmext(0xffffffff));
                                    context_opts
                                        .push(ContextOption::HexagonPktStart(unwrapped_pc as u32));
                                }
                            }
                            // TODO
                            PktLoopParseBits::Other => {
                                error!("shouldn't be here, wrong pkt loop parse bits");
                                return Err(GeneratePcodeError::InvalidInstruction);
                            }
                        }
                    }
                }
            }
        }

        self.pkt_insns = self.pkt_insns + 1;
        Ok(context_opts)
    }
}
