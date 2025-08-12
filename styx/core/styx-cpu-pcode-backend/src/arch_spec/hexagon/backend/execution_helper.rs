// SPDX-License-Identifier: BSD-2-Clause
use log::{error, trace};
use styx_cpu_type::arch::hexagon::HexagonRegister;
use styx_pcode::pcode::{Opcode, SpaceName, VarnodeData};
use styx_pcode_translator::ContextOption;
use styx_processor::{cpu::CpuBackendExt, memory::Mmu};

use super::decode_info::{DuplexInsClass, PktLoopParseBits};
use crate::{
    arch_spec::hexagon::{backend::PacketLocation, dotnew, pkt_semantics::DEST_REG_OFFSET},
    execute_pcode::PcodeHelpers,
    memory::sized_value::SizedValue,
    pcode_gen::GeneratePcodeError,
    register_manager::RegisterManager,
    PcodeBackend,
};

use super::{HexagonExecutionHelper, HexagonPcodeBackend, PktState};

#[derive(Debug)]
pub struct DefaultHexagonExecutionHelper {
    pc: Option<u64>,
    pc_varnode: VarnodeData,
    banked_pc: Option<u64>,
    internal_pc: u64,
}

impl DefaultHexagonExecutionHelper {
    fn handle_duplex_immext(
        &self,
        backend: &mut HexagonPcodeBackend,
        parse_next: PktLoopParseBits,
        insn_next: u32,
        unwrapped_pc: u32,
    ) {
        // This is only needed for immext
        if parse_next == PktLoopParseBits::Duplex && insn_next != 0 {
            trace!("duplex immext is coming up");

            backend.update_context(
                PacketLocation::Now,
                ContextOption::HexagonDuplexNext(unwrapped_pc + 6),
            );
            backend.update_context(
                PacketLocation::NextInstr,
                ContextOption::HexagonDuplexNext(0),
            );
        }
    }
    fn handle_dotnew(
        &mut self,
        insn_data: u32,
        backend: &mut HexagonPcodeBackend,
        dotnew_regs_written: &Vec<Option<u64>>,
        dotnew_instructions: u32,
    ) {
        match dotnew::parse_dotnew(insn_data) {
            Some(referenced_dotnew_pkt) => {
                trace!(
                    "dotnew: this is a dotnew packet, finding register at {} - {} within {:?}",
                    dotnew_instructions,
                    referenced_dotnew_pkt,
                    dotnew_regs_written
                );
                let location = dotnew_instructions - referenced_dotnew_pkt;
                let register_num = dotnew_regs_written[location as usize].unwrap();
                trace!("dotnew: this is a dotnew packet, setting context opts");

                // Set, then reset
                backend.update_context(
                    PacketLocation::Now,
                    ContextOption::HexagonDotnew(register_num as u32),
                );
                backend.update_context(PacketLocation::Now, ContextOption::HexagonHasnew(1));
                backend.update_context(PacketLocation::NextInstr, ContextOption::HexagonDotnew(0));
                backend.update_context(PacketLocation::NextInstr, ContextOption::HexagonHasnew(0));
            }
            None => {
                trace!("dotnew: this isn't a dotnew insn")
            }
        }
    }
    fn detect_hwloop_start_of_packet(
        &mut self,
        backend: &mut HexagonPcodeBackend,
        parse_now: PktLoopParseBits,
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
        // a hwloop terminates when lc0/lc1 == 1
        // so it will never get set to zero after the hwloop executes
        trace!("hwloop help: lc0 {} lc1 {}", lc0, lc1);

        // check if this packet is the last packet in a hardware loop
        // these are from the manual, section 10.6
        if lc0 > 1 || lc1 > 1 {
            // last in loop 1
            let pkt_endloop = if parse_now == PktLoopParseBits::NotEndOfPacket1
                && parse_next == PktLoopParseBits::NotEndOfPacket2
            {
                trace!("hwloop help: last in loop 1");
                2
            }
            // last in loop 0
            else if parse_now == PktLoopParseBits::NotEndOfPacket2
                && (parse_next == PktLoopParseBits::NotEndOfPacket1
                    || parse_next == PktLoopParseBits::EndOfPacket
                    // Is this undocumented? the assembler will happily make endloop0
                    // spit out a duplex as last instruction, but
                    // this case isn't covered in the manual AFAICT.
                    // Endloop1 and 01 are fine since they must be padded with at least 2 nops.
                    || parse_next == PktLoopParseBits::Duplex)
            {
                trace!("hwloop help: last in loop 0");
                1
            }
            // last in loop 0 and 1
            else if parse_now == PktLoopParseBits::NotEndOfPacket2
                && parse_next == PktLoopParseBits::NotEndOfPacket2
            {
                trace!("hwloop help: last in loop 0 and loop 1");
                3
            }
            // not last pkt in loop
            else {
                trace!("hwloop help: not the last packet in a hwloop");
                0
            };

            if pkt_endloop > 0 {
                backend.update_context(
                    PacketLocation::PktEnd,
                    ContextOption::HexagonEndloop(pkt_endloop),
                );
                backend.update_context(PacketLocation::PktStart, ContextOption::HexagonEndloop(0));
            }
        }
        Ok(())
    }

    fn match_predicate(vn: &VarnodeData) -> Option<usize> {
        let pred_start = 0x94;
        let pred_end = 0x97;

        if vn.space == SpaceName::Register {
            let mut offset = vn.offset;
            if vn.offset >= DEST_REG_OFFSET {
                offset -= DEST_REG_OFFSET;
            }

            trace!("offset is {}", offset);

            if offset >= pred_start && offset <= pred_end {
                Some((offset - pred_start) as usize)
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl Default for DefaultHexagonExecutionHelper {
    fn default() -> Self {
        Self {
            pc: None,
            banked_pc: None,
            internal_pc: Default::default(),
            pc_varnode: VarnodeData {
                space: SpaceName::Ram,
                offset: 0,
                size: 4,
            },
        }
    }
}

impl HexagonExecutionHelper for DefaultHexagonExecutionHelper {
    fn isa_pc(&self) -> u64 {
        self.pc.unwrap_or(0)
    }
    // could probably do the double jump logic here
    fn set_isa_pc(&mut self, value: u64, backend: &mut PcodeBackend) {
        if let Some(_) = self.pc {
            trace!("banking pc set");
            if let None = self.banked_pc {
                self.banked_pc = Some(value);
            } else {
                trace!("banking pc IGNORE - was already set earlier (works for double jump)");
            }
        } else {
            // TODO: dry, reuse fn in post execute packet
            trace!("first pc set, not banking");
            self.pc = Some(value);
            self.internal_pc = value;

            RegisterManager::write_register(
                backend,
                HexagonRegister::Pc.into(),
                SizedValue::from(self.pc.unwrap() as u32),
            )
            .unwrap();
        }
    }

    fn internal_pc(&self) -> u64 {
        trace!("internal pc is now {}", self.internal_pc);
        self.internal_pc
    }
    fn set_internal_pc(&mut self, value: u64, _backend: &mut PcodeBackend) {
        trace!("set internal pc to {}", value);
        self.internal_pc = value;
    }

    fn pre_insn_fetch(
        &mut self,
        backend: &mut HexagonPcodeBackend,
        mmu: &mut Mmu,
        prev_state: &PktState,
        pc: u32,
    ) -> Result<PktState, crate::pcode_gen::GeneratePcodeError> {
        // Duplex always ends the packet
        match prev_state {
            PktState::FirstDuplex(_) | PktState::PktStartedFirstDuplex(_) => {
                trace!("the previous instruction was a duplex, ending the packet.");
                return Ok(PktState::PktEnded(None));
            }
            _ => {}
        }

        trace!("fetching 4 instruction words from memory");

        // Get the PC
        self.pc_varnode.offset = pc as u64;
        trace!("got pc is {}", pc);

        match mmu.read_u128_le_virt_code(self.pc_varnode.offset, &mut backend.internal_backend) {
            Ok(insn_data_wide) => {
                let insn_data = (insn_data_wide & 0xffffffff) as u32;
                let insn_next = ((insn_data_wide >> 32) & 0xffffffff) as u32;
                let insn_next1 = ((insn_data_wide >> 64) & 0xffffffff) as u32;
                let insn_next2 = ((insn_data_wide >> 96) & 0xffffffff) as u32;

                let parse_data = PktLoopParseBits::new_from_insn(insn_data);
                let parse_next = PktLoopParseBits::new_from_insn(insn_next);

                // This should be run every fetch
                self.handle_duplex_immext(backend, parse_next, insn_next, pc);

                let insn_array = [insn_data, insn_next, insn_next1, insn_next2];

                trace!("parse info is {:?}", parse_data);
                return match parse_data {
                    PktLoopParseBits::Duplex => match prev_state {
                        PktState::PktEnded(_) => Ok(PktState::PktStartedFirstDuplex(insn_array)),
                        _ => Ok(PktState::FirstDuplex(insn_array)),
                    },
                    PktLoopParseBits::NotEndOfPacket1 | PktLoopParseBits::NotEndOfPacket2 => {
                        match prev_state {
                            PktState::InsidePacket(_) | PktState::PktStarted(_) => {
                                Ok(PktState::InsidePacket(insn_array))
                            }
                            PktState::PktEnded(_) => Ok(PktState::PktStarted(insn_array)),
                            _ => unreachable!("invalid packet sequence"),
                        }
                    }
                    PktLoopParseBits::EndOfPacket => match prev_state {
                        PktState::PktEnded(_) => Ok(PktState::PktStandalone(insn_array)),
                        PktState::InsidePacket(_) | PktState::PktStarted(_) => {
                            Ok(PktState::PktEnded(Some(insn_data)))
                        }
                        _ => unreachable!("invalid packet sequence"),
                    },
                    PktLoopParseBits::Other => unreachable!("invalid packet sequence"),
                };
            }
            Err(e) => {
                error!("couldn't prefetch the next insn from MMU: {:?}", e);
                return Err(GeneratePcodeError::InvalidAddress);
            }
        }
    }

    fn post_packet_fetch(&mut self, _backend: &mut HexagonPcodeBackend) {}

    // These are key

    fn first_pkt(&mut self, backend: &mut HexagonPcodeBackend, pc: u32) {
        backend.update_context(
            PacketLocation::Now,
            ContextOption::HexagonImmext(0xffffffff),
        );
        backend.update_context(PacketLocation::Now, ContextOption::HexagonPktStart(pc));
    }

    fn pkt_started(
        &mut self,
        backend: &mut HexagonPcodeBackend,
        instrs: [u32; 4],
        pc: u32,
    ) -> Result<(), GeneratePcodeError> {
        let parse_now = PktLoopParseBits::new_from_insn(instrs[0]);
        let parse_next = PktLoopParseBits::new_from_insn(instrs[1]);

        self.detect_hwloop_start_of_packet(backend, parse_now, parse_next)?;

        backend.update_context(PacketLocation::Now, ContextOption::HexagonPktStart(pc));
        Ok(())
    }

    fn pkt_inside(
        &mut self,
        _backend: &mut HexagonPcodeBackend,
        _instrs: [u32; 4],
    ) -> Result<(), GeneratePcodeError> {
        trace!("hexagon prefetch is middle of pkt");
        Ok(())
    }

    fn pkt_ended(
        &mut self,
        backend: &mut HexagonPcodeBackend,
        insn: Option<u32>,
        dotnew_regs_written: &Vec<Option<u64>>,
        dotnew_instructions: u32,
    ) -> Result<(), GeneratePcodeError> {
        // A dotnew instruction will always come at the end of a packet.
        // i.e. not a duplex
        if let Some(insn_data) = insn {
            self.handle_dotnew(insn_data, backend, dotnew_regs_written, dotnew_instructions);
        }
        Ok(())
    }

    fn pkt_first_duplex(
        &mut self,
        backend: &mut HexagonPcodeBackend,
        instrs: [u32; 4],
    ) -> Result<(), GeneratePcodeError> {
        let insn_data = instrs[0];
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

        backend.update_context(
            PacketLocation::Now,
            ContextOption::HexagonSubinsn(duplex_slots.0 as u32),
        );
        backend.update_context(
            PacketLocation::NextInstr,
            ContextOption::HexagonSubinsn(duplex_slots.1 as u32),
        );
        // Clear it after all is done.
        // Remember, a duplex always ends a packet
        backend.update_context(PacketLocation::PktStart, ContextOption::HexagonSubinsn(0));

        Ok(())
    }

    fn post_packet_execute(&mut self, backend: &mut HexagonPcodeBackend) {
        trace!("post packet execute called");
        if let Some(banked_pc) = self.banked_pc {
            trace!("banked pc was set, setting pc to {:?}", self.banked_pc);
            self.pc = Some(banked_pc);
            self.internal_pc = banked_pc;
            self.banked_pc = None;

            trace!("register manager write register self.pc={:?}", self.pc);
            RegisterManager::write_register(
                &mut backend.internal_backend,
                HexagonRegister::Pc.into(),
                SizedValue::from(self.pc.unwrap() as u32),
            )
            .unwrap();
        }
    }

    // TODO: in the future, maybe also give the instructions to figure this out faster,
    // avoiding traverseing the whole pcode array
    fn sequence(
        &mut self,
        backend: &mut HexagonPcodeBackend,
        pkt: &Vec<Vec<styx_pcode::pcode::Pcode>>,
        ordering: &mut smallvec::SmallVec<[usize; 4]>,
    ) {
        trace!("starting sequencer");

        // Keep track of predicates written
        let mut predicates_written_where = [None, None, None, None];
        let mut reorder_write_predicates = false;
        let mut remains = [true, true, true, true];
        let mut looking = [false, false, false, false];

        for (i, insn) in pkt.iter().enumerate() {
            for pcode in insn {
                trace!("pcode output {:?}", pcode.output);
                if let Some(vn) = &pcode.output {
                    if let Some(pred_idx) = Self::match_predicate(&vn) {
                        trace!("pred_idx {pred_idx}");

                        predicates_written_where[pred_idx] = Some(i);

                        if reorder_write_predicates && looking[pred_idx] {
                            looking[pred_idx] = false;
                            remains[i] = false;
                            ordering.push(i);

                            trace!(
                                "updated ordering: remains {:?}, ordering {:?}",
                                remains,
                                ordering,
                            );
                        }
                    }
                }

                if pcode.opcode == Opcode::CallOther {
                    let op_index = backend
                        .internal_backend
                        .space_manager
                        .read(pcode.get_input(0))
                        .unwrap()
                        .to_u64()
                        .unwrap();
                    let name = backend
                        .internal_backend
                        .pcode_generator
                        .user_op_name(op_index as u32);
                    trace!("at a callother with name {:?}", name);

                    // If newreg, we suddenly need to care
                    if let Some("newreg") = name {
                        // What predicate is it?
                        let reg = pcode.get_input(1);
                        trace!("register got input to callother {:?}", reg);
                        if let Some(pred_idx) = Self::match_predicate(&reg) {
                            trace!("at a newreg with a predicate");

                            // was the predicate not already referenced?
                            if let None = predicates_written_where[pred_idx] {
                                trace!("requires reordering.");

                                reorder_write_predicates = true;
                                looking[pred_idx] = true;
                            }
                        }
                    }
                }
            }
            trace!(
                "finished parsing insn {i}, reorder_write_predicates={reorder_write_predicates}"
            );
        }

        for i in 0..pkt.len() {
            if remains[i] {
                trace!("insn {i} remains!");
                ordering.push(i);
            }
        }

        trace!("finished sequencing ordering={:?}", ordering);
    }
}
