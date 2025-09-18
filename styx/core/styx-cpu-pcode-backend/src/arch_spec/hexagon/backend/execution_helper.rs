// SPDX-License-Identifier: BSD-2-Clause
use log::{error, trace};
use styx_cpu_type::arch::{
    backends::{ArchRegister, BasicArchRegister},
    hexagon::{variants::HexagonGeneralRegistersWithHvx, HexagonRegister},
};
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
    pcode_gen::{GeneratePcodeError, RegisterTranslator},
    register_manager::RegisterManager,
};

use super::{HexagonExecutionHelper, HexagonPcodeBackend, PktState};

#[derive(Debug, Clone)]
pub struct DefaultHexagonExecutionHelper {
    pc: Option<u64>,
    pc_varnode: VarnodeData,
}

impl DefaultHexagonExecutionHelper {
    /// Handle a duplex immediate extenion. This is the case where
    /// an immediate extension applies to a duplex instruction.
    fn handle_duplex_immext(
        &self,
        backend: &mut HexagonPcodeBackend,
        parse_next: PktLoopParseBits,
        unwrapped_pc: u32,
    ) {
        // Check section 10.3 on constraints -- "A duplex can contain only one constant-extended
        // instruction, and it must appear in the Slot 1 position."
        //
        // Slot 1 executes _before_ slot 0, so the immediate extension applies to the first instruction
        // in the duplex.
        //
        // The immediate extension instruction in the SLASPEC basically handles things
        // differently based on if we indicate a duplex immediate extension or not.
        //
        // The immediate extension handler uses the `globalset` directive to set the
        // immediate extension context option at a later point. This later point
        // (as a memory address indicating the start of the instruction)
        // is specified by the value in the DuplexNext context option.
        //
        // The DuplexNext option is only needed during decoding the
        // immediate extension, so we can reset it at the start of the
        // duplex (the next instruction).
        //
        // We set the DuplexNext to the PC + 6 (aka the "middle of the
        // next duplex instruction") because likely due to endianness.  Table 10.4 indicates
        // Slot 0 is in the lower bytes and Slot 1 is in the higher bytes, and the lower bytes
        // are parsed first so we need to set the constant extender for the _second_ parsed
        // duplex instruction.
        //
        // This actually leads to duplex instructions being in the opposite order.
        // Since packets are atomic, the execution semantics don't really matter (whether slot 0/1 executes first)
        // in this case
        if parse_next == PktLoopParseBits::Duplex {
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

    /// Hook at the beginning of a packet to determine
    /// if this packet represents the end of a hardware loop.
    fn detect_hwloop_start_of_packet(
        &mut self,
        backend: &mut HexagonPcodeBackend,
        parse_now: PktLoopParseBits,
        parse_next: PktLoopParseBits,
    ) -> Result<(), GeneratePcodeError> {
        // Hardware loop handling needs to be done here.
        //
        // The LC0 and LC1 registers are used as loop counters
        // for hardware loops. See the beginning of
        // section 8.2 for more details.
        let lc0 = backend
            .read_register::<u32>(HexagonRegister::Lc0)
            .map_err(|_| GeneratePcodeError::InvalidAddress)?;
        let lc1 = backend
            .read_register::<u32>(HexagonRegister::Lc1)
            .map_err(|_| GeneratePcodeError::InvalidAddress)?;

        // This uses lc0, lc1, and the first two parse fields
        // in the packet to determine hwloop status.
        //
        // The last instruction in a packet that is at the end of a
        // hardware loop requires being marked with a context option.
        // See HardwareLoopStatus::parse and the corresponding struct
        // for more information on the context option and parsing
        // logic.
        //
        // We do not want to have the "endloop" context option set
        // after the last instruction in the packet. Since
        // the endloop context option is always for the end of the packet,
        // we can clear it at the start of the next packet (see SavedContextOptions
        // to understand the PacketLocation semantics).
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

    fn match_predicate_varnode(vn: &VarnodeData, backend: &HexagonPcodeBackend) -> Option<usize> {
        // Just check if our varnode's offset is within the range
        // of the predicate start and end offsets, and sanity check that
        // the varnode size is 1 byte.
        if vn.space == SpaceName::Register && vn.size == 1 {
            Self::match_predicate(vn.offset, backend)
        } else {
            None
        }
    }

    /// Determine whether or not a register varnode
    /// is one of the four predicate registers.
    pub(crate) fn match_predicate(reg_offset: u64, backend: &HexagonPcodeBackend) -> Option<usize> {
        // Each predicate is 1 byte. See
        // section 2.2.5 for this.

        // NOTE: this assumes that the four predicate registers are contiguous in
        // the register space, but this should hold true as the four predicate registers
        // comprise one larger control register C4 (see table 2-2).
        //
        // We unwrap since something is seriously wrong if we can't access these values.
        let pred_start = backend
            .pcode_generator
            .get_register(&ArchRegister::Basic(BasicArchRegister::Hexagon(
                HexagonRegister::P0,
            )))
            .expect("can't get p0 register as varnode")
            .offset;
        let pred_end = backend
            .pcode_generator
            .get_register(&ArchRegister::Basic(BasicArchRegister::Hexagon(
                HexagonRegister::P3,
            )))
            .expect("can't get p0 register as varnode")
            .offset;

        // This is because we want make some edits on a copy of this value
        let mut reg_offset = reg_offset;

        if reg_offset >= DEST_REG_OFFSET {
            reg_offset -= DEST_REG_OFFSET;
        }

        trace!("reg_offset is {reg_offset}, pred_start is {pred_start}, pred_end is {pred_end}");

        if reg_offset >= pred_start && reg_offset <= pred_end {
            trace!("returning {}", reg_offset - pred_start);
            Some((reg_offset - pred_start) as usize)
        } else {
            trace!("not returning anything");
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

    fn set_isa_pc(&mut self, value: u64, backend: &mut HexagonPcodeBackend) {
        self.pc = Some(value);

        // While we maintain an internal value for the program counter,
        // we also want to make sure the backing register varnode space
        // has an accurate PC.
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
        // Duplex always ends the packet - section 10.3,
        // duplexes are in slots 0 and 1, which are the last
        // 2 slots in a packet.
        //
        // As such, we can conclude that the second sub-instruction
        // in a duplex is the last instruction in a packet.
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

        // We read four instructions, since some decoding requires looking
        // ahead. Four instructions because every packet in Hexagon is at most
        // four instructions.
        let insn_data_wide = mmu
            .read_u128_le_virt_code(self.pc_varnode.offset, backend)
            .with_context(|| "couldn't prefetch the next insn from MMU")
            .map_err(|e| HexagonFetchDecodeError::Other(e.into()))?;

        // Extract out the four instructions.
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

        // Get Parse bits for current and next instruction.
        // See Section 10.5 for what this is generally used for.
        let parse_data = insn_data.parse();
        let parse_next = insn_next.parse();

        // This should be run every fetch - check if the next instruction
        // is a duplex. Currently only used by immediate extension.
        self.handle_duplex_immext(backend, parse_next, pc);

        let insn_array = [insn_data, insn_next, insn_next1, insn_next2];

        trace!("parse info is {parse_data:?}");
        trace!("1st instruction is {:#010x}", insn_data.raw_value());
        trace!("2nd instruction is {:#010x}", insn_next.raw_value());
        trace!("3rd instruction is {:#010x}", insn_next1.raw_value());
        trace!("4th instruction is {:#010x}", insn_next2.raw_value());

        match parse_data {
            PktLoopParseBits::Duplex => match prev_state {
                // Last instruction was the end of a packet and current instruction is the
                // first sub-instruction in a duplex that starts a packet.
                PktState::PktEnded(_) => Ok(PktState::PktStartedFirstDuplex(insn_array)),
                // This is the first duplex sub-instruction in the sequence of two
                // duplex instructions.
                _ => Ok(PktState::FirstDuplex(insn_array)),
            },
            PktLoopParseBits::NotEndOfPacket1 | PktLoopParseBits::NotEndOfPacket2 => {
                match prev_state {
                    // We're inside a packet (either second or third instruction).
                    PktState::InsidePacket(_) | PktState::PktStarted(_) => {
                        Ok(PktState::InsidePacket(insn_array))
                    }
                    // We're the first in a packet. There is no Parse sequence
                    // to indicate the start of a packet, so we must determine this
                    // by looking at the previous packet's state.
                    //
                    // (see section 10.5 for context)
                    PktState::PktEnded(_) => Ok(PktState::PktStarted(insn_array)),

                    _ => unreachable!("invalid packet sequence"),
                }
            }
            PktLoopParseBits::EndOfPacket => match prev_state {
                // The end of a packet followed by another end of packet means this
                // packet has only 1 instruction.
                PktState::PktEnded(_) => Ok(PktState::PktStandalone(insn_array)),
                // Other cases indicate this is the end of a packet with
                // more than 1 instruction.
                PktState::InsidePacket(_) | PktState::PktStarted(_) => {
                    Ok(PktState::PktEnded(Some(insn_data)))
                }
                _ => unreachable!("invalid packet sequence"),
            },
        }
    }

    fn post_packet_fetch(&mut self, _backend: &mut HexagonPcodeBackend) {}

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

    /// This hook runs after pre_insn_fetch but before the instruction
    /// actually is fetched. Its role is to look through the ICLASS
    /// field and find each duplex sub-instruction type
    /// (see manual table 10-4).
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

        // Our SLASPEC requires the "subinsn" context option
        // to be set to decode a duplex correctly because
        // the SLASPEC can't find the sub-instruction types
        // due to lookahead/behind constraints in Sleigh.
        backend.update_context(
            PacketLocation::Now,
            ContextOption::HexagonSubinsn(duplex_slots.0 as u32),
        );
        backend.update_context(
            PacketLocation::NextInstr,
            ContextOption::HexagonSubinsn(duplex_slots.1 as u32),
        );

        // Clear it after both duplexes.
        //
        // Remember, a duplex always ends a packet, so the first instruction
        // after the two duplexes is the start of a new packet.
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
                    if let Some(pred_idx) = Self::match_predicate_varnode(vn, backend) {
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
                        if let Some(pred_idx) = Self::match_predicate_varnode(reg, backend) {
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
