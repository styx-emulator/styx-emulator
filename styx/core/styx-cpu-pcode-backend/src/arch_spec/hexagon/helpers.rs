use crate::arch_spec::generator_helper::CONTEXT_OPTION_LEN;
use crate::arch_spec::hexagon::dotnew;
use crate::{arch_spec::GeneratorHelp, pcode_gen::GeneratePcodeError};
use crate::{PcodeBackend, SharedStateKey};
use log::{error, trace};
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use styx_cpu_type::arch::hexagon::HexagonRegister;
use styx_pcode::pcode::{SpaceName, VarnodeData};
use styx_pcode_translator::ContextOption;
use styx_processor::cpu::CpuBackendExt;
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

#[derive(Debug, Clone)]
enum SubinstructionData {
    EndDuplex(u32),
    EndDuplexEndPacket(u32),
    StartDuplex(u32),
}

// this is to avoid https://smallcultfollowing.com/babysteps/blog/2018/11/01/after-nll-interprocedural-conflicts/
#[derive(Debug, Clone)]
struct HexagonGeneratorHelperState {
    // Stores if the last instruction was the end of a packet.
    pub last_insn_was_end_of_pkt: bool,
    pub duplex_ended: bool,
    pub first_insn_setup: bool,
    pub pkt_insns: usize,
    pub duplex_next_set: bool,
    pub pkt_endloop: u32,
    pub pkt_endloop_cleared: bool,
    pub dotnew_should_unset: bool,
    pub latest_endloop: u64,
}

#[derive(Debug, Clone)]
pub struct HexagonGeneratorHelper {
    // map code address -> subinsn type
    subinsn_map: FxHashMap<u64, SubinstructionData>,
    pc_varnode: VarnodeData,
    state: HexagonGeneratorHelperState,
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
            state: HexagonGeneratorHelperState {
                last_insn_was_end_of_pkt: true,
                // Presumably this needs to be set once, and never again.
                // TODO: make sure this is true by trying an instruction that would actually use an immext
                first_insn_setup: true,
                pkt_insns: 0,
                duplex_ended: false,
                duplex_next_set: false,
                pkt_endloop: 0,
                pkt_endloop_cleared: true,
                dotnew_should_unset: false,
                latest_endloop: 0,
            },
        }
    }
}

impl HexagonGeneratorHelperState {
    fn handle_first_insn(&mut self, context_opts: &mut SmallVec<[ContextOption; 4]>) {
        self.first_insn_setup = false;

        context_opts.push(ContextOption::HexagonImmext(0xffffffff));
    }

    fn mark_end_of_pkt(&mut self, backend: &mut PcodeBackend, next_start_pc: u64) {
        // Mark that the "last instruction was the end of a packet"
        // and update the location of the end of the packet
        self.last_insn_was_end_of_pkt = true;
        backend
            .shared_state
            .insert(SharedStateKey::HexagonPktStart, next_start_pc as u128);
    }

    fn handle_endloop_set(
        &mut self,
        unwrapped_pc: u64,
        context_opts: &mut SmallVec<[ContextOption; 4]>,
    ) {
        if self.pkt_endloop != 0 {
            context_opts.push(ContextOption::HexagonEndloop(self.pkt_endloop));

            // HACK: we need to clear "endloop" for all instructions
            // up to and including the first packet after the loop ends
            // This stores that.
            if unwrapped_pc > self.latest_endloop {
                self.latest_endloop = unwrapped_pc;
            }

            self.pkt_endloop = 0;
            self.pkt_endloop_cleared = false;
        }
    }

    fn handle_duplex_immext(
        &mut self,
        parse_next: PktLoopParseBits,
        insn_next: u32,
        unwrapped_pc: u64,
        context_opts: &mut SmallVec<[ContextOption; 4]>,
    ) {
        // This is only needed for immext
        if parse_next == PktLoopParseBits::Duplex && insn_next != 0 {
            context_opts.push(ContextOption::HexagonDuplexNext(unwrapped_pc as u32 + 6));
            self.duplex_next_set = true;
        } else if self.duplex_next_set {
            self.duplex_next_set = false;
            context_opts.push(ContextOption::HexagonDuplexNext(0));
        }
    }
}

impl HexagonGeneratorHelper {
    fn handle_start_of_pkt(
        &mut self,
        backend: &mut PcodeBackend,
        context_opts: &mut SmallVec<[ContextOption; 4]>,
        unwrapped_pc: u64,
    ) {
        self.detect_handle_branch(backend, unwrapped_pc);

        context_opts.push(ContextOption::HexagonPktStart(unwrapped_pc as u32));

        // endloop is cleared at the start of the next packet
        if self.state.pkt_endloop == 0 && !self.state.pkt_endloop_cleared {
            context_opts.push(ContextOption::HexagonEndloop(0));
        }

        if unwrapped_pc > self.state.latest_endloop {
            self.state.pkt_endloop_cleared = true;
        }
        self.state.pkt_insns = 0;
    }

    fn handle_dotnew(
        &mut self,
        insn_data: u32,
        backend: &mut PcodeBackend,
        context_opts: &mut SmallVec<[ContextOption; 4]>,
    ) {
        if self.state.dotnew_should_unset {
            trace!("unsetting hexagon hasnew");

            // there's no point in setting dotnew, it's only ever used if
            // hasnew is 1, but just for good measure
            context_opts.push(ContextOption::HexagonHasnew(0));
            context_opts.push(ContextOption::HexagonDotnew(0));

            self.state.dotnew_should_unset = false;
        }

        match dotnew::parse_dotnew(insn_data) {
            Some(referenced_dotnew_pkt) => {
                // get current start
                if let Some(current) = backend
                    .shared_state
                    .get(&SharedStateKey::HexagonTrueInsnCount)
                {
                    trace!(
                        "dotnew: this is a dotnew packet, finding register at {} - {}",
                        *current,
                        referenced_dotnew_pkt
                    );
                    if let Some(register_num) =
                        backend
                            .shared_state
                            .get(&SharedStateKey::HexagonInsnRegDest(
                                (*current - referenced_dotnew_pkt as u128) as usize,
                            ))
                    {
                        trace!("dotnew: this is a dotnew packet, setting context opts");
                        context_opts.push(ContextOption::HexagonDotnew(*register_num as u32));
                        context_opts.push(ContextOption::HexagonHasnew(1));
                        self.state.dotnew_should_unset = true;
                    }
                }
            }
            None => {
                trace!("dotnew: this isn't a dotnew insn")
            }
        }

        // TODO: put our dotnew handlers here
        // if dotnew_insn {
        // off = get dotnew offset(dst, offset)
        // get Q current - off -> regval
        //  set hasnew 1
        //  set dotnew Q
        // }
    }
    fn handle_duplex(
        &mut self,
        _backend: &mut PcodeBackend,
        context_opts: &mut SmallVec<[ContextOption; 4]>,
        saved_last_insn_was_end_of_pkt: bool,
        unwrapped_pc: u64,
        insn_data: u32,
        parse_next: PktLoopParseBits,
        parse_next1: PktLoopParseBits,
    ) -> Result<(), GeneratePcodeError> {
        let insclass = ((insn_data >> 28) & 0b1110) | ((insn_data >> 13) & 0b1);
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

        context_opts.push(ContextOption::HexagonSubinsn(duplex_slots.0 as u32));

        // First insn in duplex is a pkt start
        if self.state.first_insn_setup {
            self.state.first_insn_setup = false;

            // If standalone, this should be EndDuplexEndPacket

            // D I Ie or D Ie
            if parse_next == PktLoopParseBits::EndOfPacket
                || ((parse_next == PktLoopParseBits::NotEndOfPacket1
                    || parse_next == PktLoopParseBits::NotEndOfPacket2)
                    && parse_next1 == PktLoopParseBits::EndOfPacket)
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
                    SubinstructionData::EndDuplexEndPacket(duplex_slots.1 as u32),
                );
            }

            context_opts.push(ContextOption::HexagonPktStart(unwrapped_pc as u32));
            // None of this should require last_pkt_ended, as we're not at the end of an instruction
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
        else if self.state.pkt_insns <= 1 &&
                                // D I (end) or I D I (end)
                                (parse_next == PktLoopParseBits::EndOfPacket ||
                                        // D I I (end)
                                         ( (parse_next == PktLoopParseBits::NotEndOfPacket1 || parse_next == PktLoopParseBits::NotEndOfPacket2)
                                              && parse_next1 == PktLoopParseBits::EndOfPacket))
        {
            trace!("this duplex instruction pair does not terminate a packet");
            self.subinsn_map.insert(
                unwrapped_pc + 2,
                SubinstructionData::EndDuplex(duplex_slots.1 as u32),
            );

            // Start of packet
            if saved_last_insn_was_end_of_pkt {
                self.state.pkt_insns = 0;
            }
        }
        // Emit pkt start if we are in IID, D, or ID scenario (should be EndDuplexEndPacket)
        // Remaining case is I I D or I D
        else {
            trace!("this duplex instruction pair DOES terminate a packet");
            self.subinsn_map.insert(
                unwrapped_pc + 2,
                SubinstructionData::EndDuplexEndPacket(duplex_slots.1 as u32),
            );
        }
        Ok(())
    }

    fn detect_hwloop_start_of_packet(
        &mut self,
        backend: &mut PcodeBackend,
        pkt_type: PktLoopParseBits,
        parse_next: PktLoopParseBits,
    ) -> Result<(), GeneratePcodeError> {
        // Hardware loop handling needs to be done here.
        // There shouldn't be duplexes at the beginning of a hwloop?
        let lc0 = backend
            .read_register::<u32>(HexagonRegister::Lc0)
            .map_err(|_| GeneratePcodeError::InvalidAddress)?;
        let lc1 = backend
            .read_register::<u32>(HexagonRegister::Lc1)
            .map_err(|_| GeneratePcodeError::InvalidAddress)?;

        // check for hardware loop
        // check if lc0/lc1 is greater than 1, since
        //
        trace!("hwloop help: lc0 {} lc1 {}", lc0, lc1);

        // check if this packet is the last packet in a hardware loop
        if lc0 > 1 || lc1 > 1 {
            // last in loop 1
            if pkt_type == PktLoopParseBits::NotEndOfPacket1 {
                trace!("hwloop help: last in loop 1");
                self.state.pkt_endloop = 2;
            }
            // last in loop 0
            else if pkt_type == PktLoopParseBits::NotEndOfPacket2
                && (parse_next == PktLoopParseBits::NotEndOfPacket1
                    || parse_next == PktLoopParseBits::EndOfPacket)
            {
                trace!("hwloop help: last in loop 0");
                self.state.pkt_endloop = 1;
            }
            // last in loop 0 and 1
            else if pkt_type == PktLoopParseBits::NotEndOfPacket2
                && parse_next == PktLoopParseBits::NotEndOfPacket2
            {
                trace!("hwloop help: last in loop 0 and loop 1");
                self.state.pkt_endloop = 3;
            }
            // not last pkt in loop
            else {
                trace!("hwloop help: not the last packet in a hwloop");
                self.state.pkt_endloop = 0;
            }
        }
        Ok(())
    }

    fn detect_handle_branch(&self, backend: &mut PcodeBackend, unwrapped_pc: u64) {
        // In case of branching, we need to do a quick sanity check
        // to make sure that value in our shared state matches, otherwise
        // we need to update it here.
        match backend.shared_state.get(&SharedStateKey::HexagonPktStart) {
            Some(next_pkt_start) if *next_pkt_start != unwrapped_pc as u128 => {
                trace!("helper detected a branch, updating shared state for consistency");
                backend
                    .shared_state
                    .insert(SharedStateKey::HexagonPktStart, unwrapped_pc as u128);
            }
            _ => {}
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
        let saved_last_insn_was_end_of_pkt = self.state.last_insn_was_end_of_pkt;
        self.state.last_insn_was_end_of_pkt = false;

        // Get the PC
        match backend.pc() {
            Err(e) => {
                error!("Could not fetch PC from backend: {:?}", e);
                return Err(GeneratePcodeError::InvalidAddress);
            }
            Ok(unwrapped_pc) => {
                self.pc_varnode.offset = unwrapped_pc;

                match self.subinsn_map.get_mut(&self.pc_varnode.offset) {
                    Some(subinsn_data) => {
                        let (duplex_ended, subinsn_type) = match subinsn_data {
                            // Update shared state to the start of the next packet, as is done in the EndPkt case later
                            SubinstructionData::EndDuplexEndPacket(ty) => {
                                trace!("in end duplex that's an end of packet, pushing the next packet and such");
                                self.state.mark_end_of_pkt(backend, unwrapped_pc + 2);

                                (true, ty)
                            }
                            SubinstructionData::EndDuplex(ty) => (true, ty),
                            SubinstructionData::StartDuplex(ty) => (false, ty),
                        };

                        self.state.duplex_ended = duplex_ended;

                        context_opts.push(ContextOption::HexagonSubinsn(*subinsn_type));

                        // Consume as we go to prevent a memory leak
                        // by having the map grow infinitely
                        self.subinsn_map.remove(&self.pc_varnode.offset);
                        self.state.pkt_insns = self.state.pkt_insns + 1;

                        return Ok(context_opts);
                    }
                    None => {}
                }

                if self.state.duplex_ended {
                    self.state.duplex_ended = false;
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
                        let _parse_next2 = PktLoopParseBits::new_from_insn(insn_next2);

                        self.state.handle_duplex_immext(
                            parse_next,
                            insn_next,
                            unwrapped_pc,
                            &mut context_opts,
                        );
                        self.handle_dotnew(insn_data, backend, &mut context_opts);

                        trace!("insn data is 0x{:x}", insn_data);

                        let pkt_type = PktLoopParseBits::new_from_insn(insn_data);
                        match pkt_type {
                            PktLoopParseBits::Duplex => self.handle_duplex(
                                backend,
                                &mut context_opts,
                                saved_last_insn_was_end_of_pkt,
                                unwrapped_pc,
                                insn_data,
                                parse_next,
                                parse_next1,
                            )?,
                            // First instruction in the program won't have anything taken care of
                            PktLoopParseBits::NotEndOfPacket1
                            | PktLoopParseBits::NotEndOfPacket2
                                if self.state.first_insn_setup =>
                            {
                                trace!(
                                    "First instruction helper has seen, setting up context opts"
                                );
                                context_opts
                                    .push(ContextOption::HexagonPktStart(unwrapped_pc as u32));
                                backend
                                    .shared_state
                                    .insert(SharedStateKey::HexagonPktStart, unwrapped_pc as u128);

                                self.state.handle_first_insn(&mut context_opts);
                            }

                            // The start of a new packet
                            // Based on: https://github.com/toshipiazza/ghidra-plugin-hexagon/blob/main/Ghidra/Processors/Hexagon/src/main/java/ghidra/app/plugin/core/analysis/HexagonPacketAnalyzer.java
                            // They also set pkt_next, but pkt_next isn't used in the slaspec (thankfully).
                            PktLoopParseBits::NotEndOfPacket1
                            | PktLoopParseBits::NotEndOfPacket2
                                if saved_last_insn_was_end_of_pkt =>
                            {
                                trace!("hexagon start of packet");

                                // These are not required in the "start and end of packet"
                                // as a hardware loop will always have 4 slots (with no ops)
                                self.detect_hwloop_start_of_packet(backend, pkt_type, parse_next)?;

                                self.handle_start_of_pkt(backend, &mut context_opts, unwrapped_pc);
                            }
                            PktLoopParseBits::NotEndOfPacket1
                            | PktLoopParseBits::NotEndOfPacket2 => {
                                trace!("hexagon prefetch is middle of packet");
                            }
                            PktLoopParseBits::EndOfPacket => {
                                // Special care is taken for an end of packet
                                // that is the first packet seen
                                if self.state.first_insn_setup {
                                    trace!(
                                        "First instruction helper but the packet has only 1 insn"
                                    );

                                    self.state.handle_first_insn(&mut context_opts);
                                }

                                // This is both the start and end of a packet (single insn pkt)
                                if saved_last_insn_was_end_of_pkt {
                                    trace!("start and end of pkt");
                                    // Normally, this would be handled in the "hexagon start of packet" handler,
                                    // that arm of the match is never taken if we have both a start and end of a packet.
                                    // Therefore, it is important to update the "packet start" as the start of the
                                    // single-instruction packet here.
                                    self.handle_start_of_pkt(
                                        backend,
                                        &mut context_opts,
                                        unwrapped_pc,
                                    );
                                } else {
                                    trace!("got to end of pkt");
                                }

                                // Not a duplex, so next ins is +4 away in packet distance
                                self.state.mark_end_of_pkt(backend, unwrapped_pc + 4);
                                self.state
                                    .handle_endloop_set(unwrapped_pc, &mut context_opts);
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

        self.state.pkt_insns += 1;
        Ok(context_opts)
    }
}
