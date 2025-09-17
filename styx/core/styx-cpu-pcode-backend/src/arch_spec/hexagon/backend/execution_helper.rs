// SPDX-License-Identifier: BSD-2-Clause
use log::{error, trace};
use styx_cpu_type::arch::hexagon::{variants::HexagonGeneralRegistersWithHvx, HexagonRegister};
use styx_errors::{anyhow::Context, UnknownError};
use styx_pcode::pcode::{Opcode, SpaceName, VarnodeData};
use styx_pcode_translator::ContextOption;
use styx_processor::{cpu::CpuBackendExt, memory::Mmu};

use super::{
    decode_info::{DuplexInsClass, PktLoopParseBits},
    HexagonFetchDecodeError, OutputRegisterType,
};
use crate::{
    arch_spec::hexagon::{
        backend::{
            decode_info::{GeneralHexagonInstruction, HardwareLoopStatus},
            PacketLocation,
        },
        dotnew,
        pkt_semantics::DEST_REG_OFFSET,
    },
    execute_pcode::PcodeHelpers,
    memory::sized_value::SizedValue,
    pcode_gen::GeneratePcodeError,
    register_manager::RegisterManager,
};

use super::{HexagonExecutionHelper, HexagonPcodeBackend, PktState};

#[derive(Debug, Clone)]
pub struct DefaultHexagonExecutionHelper {
    pc: Option<u64>,
    pc_varnode: VarnodeData,
}

impl DefaultHexagonExecutionHelper {
    fn handle_duplex_immext(
        &self,
        backend: &mut HexagonPcodeBackend,
        parse_next: PktLoopParseBits,
        insn_next: GeneralHexagonInstruction,
        unwrapped_pc: u32,
    ) {
        // This is only needed for immext
        if parse_next == PktLoopParseBits::Duplex && !insn_next.is_zero() {
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
        insn_data: GeneralHexagonInstruction,
        backend: &mut HexagonPcodeBackend,
        dotnew_regs_written: &Vec<OutputRegisterType>,
        dotnew_instructions: u32,
    ) {
        match dotnew::parse_dotnew(insn_data) {
            Some(referenced_dotnew_pkt) => {
                trace!(
                    "dotnew: this is a dotnew packet, finding register at {dotnew_instructions} - {referenced_dotnew_pkt} within {dotnew_regs_written:?}"
                );
                let location = dotnew_instructions - referenced_dotnew_pkt;
                if let OutputRegisterType::General(register_num) =
                    dotnew_regs_written[location as usize]
                {
                    trace!("dotnew: this is a dotnew packet, setting context opts");

                    // Set, then reset
                    backend.update_context(
                        PacketLocation::Now,
                        ContextOption::HexagonDotnew(register_num as u32),
                    );
                    backend.update_context(PacketLocation::Now, ContextOption::HexagonHasnew(1));
                    backend
                        .update_context(PacketLocation::NextInstr, ContextOption::HexagonDotnew(0));
                    backend
                        .update_context(PacketLocation::NextInstr, ContextOption::HexagonHasnew(0));
                } else {
                    unreachable!("dotnew reference was not a general register!")
                }
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

        match HardwareLoopStatus::parse(lc0, lc1, parse_now, parse_next) {
            Some(loop_status) if loop_status != HardwareLoopStatus::NotLastInLoop => {
                backend.update_context(
                    PacketLocation::PktEnd,
                    ContextOption::HexagonEndloop(loop_status as u32),
                );
                backend.update_context(PacketLocation::PktStart, ContextOption::HexagonEndloop(0));
            }
            _ => {
                trace!("not setting any context options for hardware loop, not in hwloop or not end of hwloop")
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

            trace!("offset is {offset}");

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
    fn set_isa_pc(&mut self, value: u64, backend: &mut HexagonPcodeBackend) {
        self.pc = Some(value);

        RegisterManager::write_register(
            backend,
            HexagonRegister::Pc.into(),
            SizedValue::from(self.pc.unwrap() as u32),
        )
        .unwrap();
    }

    fn pre_insn_fetch(
        &mut self,
        backend: &mut HexagonPcodeBackend,
        mmu: &mut Mmu,
        prev_state: &PktState,
        pc: u32,
    ) -> Result<PktState, HexagonFetchDecodeError> {
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
        trace!("got pc is {pc}");

        let insn_data_wide = mmu
            .read_u128_le_virt_code(self.pc_varnode.offset, backend)
            .with_context(|| "couldn't prefetch the next insn from MMU")
            .map_err(|e| HexagonFetchDecodeError::Other(e.into()))?;

        let insn_data =
            GeneralHexagonInstruction::new_with_raw_value((insn_data_wide & 0xffffffff) as u32);
        let insn_next = GeneralHexagonInstruction::new_with_raw_value(
            ((insn_data_wide >> 32) & 0xffffffff) as u32,
        );
        let insn_next1 = GeneralHexagonInstruction::new_with_raw_value(
            ((insn_data_wide >> 64) & 0xffffffff) as u32,
        );
        let insn_next2 = GeneralHexagonInstruction::new_with_raw_value(
            ((insn_data_wide >> 96) & 0xffffffff) as u32,
        );

        let parse_data = insn_data.parse();
        let parse_next = insn_next.parse();

        // This should be run every fetch
        self.handle_duplex_immext(backend, parse_next, insn_next, pc);

        let insn_array = [insn_data, insn_next, insn_next1, insn_next2];

        trace!("parse info is {parse_data:?}");
        trace!("1st instruction is {:#010x}", insn_data.raw_value());
        trace!("2nd instruction is {:#010x}", insn_next.raw_value());
        trace!("3rd instruction is {:#010x}", insn_next1.raw_value());
        trace!("4th instruction is {:#010x}", insn_next2.raw_value());

        match parse_data {
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
        instrs: [GeneralHexagonInstruction; 4],
        pc: u32,
    ) -> Result<(), GeneratePcodeError> {
        let parse_now = instrs[0].parse();
        let parse_next = instrs[1].parse();

        self.detect_hwloop_start_of_packet(backend, parse_now, parse_next)?;

        backend.update_context(PacketLocation::Now, ContextOption::HexagonPktStart(pc));
        Ok(())
    }

    fn pkt_inside(
        &mut self,
        _backend: &mut HexagonPcodeBackend,
        _instrs: [GeneralHexagonInstruction; 4],
    ) -> Result<(), GeneratePcodeError> {
        trace!("hexagon prefetch is middle of pkt");
        Ok(())
    }

    fn pkt_ended(
        &mut self,
        backend: &mut HexagonPcodeBackend,
        insn: Option<GeneralHexagonInstruction>,
        dotnew_regs_written: &Vec<OutputRegisterType>,
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
        instrs: [GeneralHexagonInstruction; 4],
    ) -> Result<(), GeneratePcodeError> {
        let insn_data = instrs[0];
        let insclass = insn_data.duplex_iclass().value();

        trace!("duplex instruction, insclass {insclass}");

        // See Table 10-5 (DUPLEX ICLASS field) in Hexagon manual for this mapping
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
                    if let Some(pred_idx) = Self::match_predicate(vn) {
                        trace!("pred_idx {pred_idx}");

                        predicates_written_where[pred_idx] = Some(i);

                        if reorder_write_predicates && looking[pred_idx] && remains[i] {
                            remains[i] = false;
                            ordering.push(i);

                            trace!("updated ordering: remains {remains:?}, ordering {ordering:?}",);
                        }
                    }
                }

                if pcode.opcode == Opcode::CallOther {
                    let op_index = backend
                        .space_manager
                        .read(pcode.get_input(0))
                        .unwrap()
                        .to_u64()
                        .unwrap();
                    let name = backend.pcode_generator.user_op_name(op_index as u32);
                    trace!("at a callother with name {name:?}");

                    // If newreg, we suddenly need to care
                    if let Some("newreg") = name {
                        // What predicate is it?
                        let reg = pcode.get_input(1);
                        trace!("register got input to callother {reg:?}");
                        if let Some(pred_idx) = Self::match_predicate(reg) {
                            trace!("at a newreg with a predicate, which always requires caring about reordering");

                            reorder_write_predicates = true;
                            looking[pred_idx] = true;
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

        trace!("finished sequencing ordering={ordering:?}");
    }
}
