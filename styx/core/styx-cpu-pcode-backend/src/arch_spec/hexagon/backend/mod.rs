// SPDX-License-Identifier: BSD-2-Clause
use std::sync::{Arc, Mutex};

use as_any::{AsAny, Downcast};
use execution_helper::DefaultHexagonExecutionHelper;
pub use generator_helper::HexagonGeneratorHelper;
use log::trace;
pub use pc_manager::HexagonPcManager;
pub use saved_context_opts::SavedContextOpts;
use smallvec::{smallvec, SmallVec};
use styx_cpu_type::{
    arch::{
        backends::{ArchRegister, ArchVariant},
        ArchitectureDef, RegisterValue,
    },
    Arch, ArchEndian, TargetExitReason,
};
use styx_errors::UnknownError;
use styx_pcode::pcode::{Opcode, Pcode, SpaceName, VarnodeData};
use styx_pcode_translator::ContextOption;
use styx_processor::{
    cpu::{CpuBackend, ExecutionReport, ReadRegisterError, WriteRegisterError},
    event_controller::EventController,
    hooks::{AddHookError, DeleteHookError, HookToken, Hookable, StyxHook},
    memory::Mmu,
};

use crate::execute_pcode;
use crate::hooks::HookManager;
use crate::{
    arch_spec::{
        hexagon::{parse_iclass, pkt_semantics::DEST_REG_OFFSET},
        GeneratorHelper, PcManager,
    },
    get_pcode::fetch_pcode,
    pcode_gen::GeneratePcodeError,
    PcodeBackend, PcodeBackendConfiguration,
};
use crate::{PCodeStateChange, DEFAULT_REG_ALLOCATION};

mod decode_info;
mod execution_helper;
mod generator_helper;
mod pc_manager;

mod saved_context_opts;

#[derive(PartialEq, Debug)]
pub enum PktState {
    PktStarted([u32; 4]),
    PktStandalone([u32; 4]),
    InsidePacket([u32; 4]),
    FirstDuplex([u32; 4]),
    PktStartedFirstDuplex([u32; 4]),
    // A duplex instruction would not want to give this information
    PktEnded(Option<u32>),
}

#[derive(Debug)]
pub enum PacketLocation {
    PktStart,
    PktEnd,
    NextInstr,
    Now,
}

#[derive(Debug)]
pub struct HexagonPcodeBackend {
    pub internal_backend: PcodeBackend,

    saved_context_opts: SavedContextOpts,
    regs_written: Vec<Vec<VarnodeData>>,
    execution_regs_written: SmallVec<[VarnodeData; DEFAULT_REG_ALLOCATION]>,
    execution_helper: Option<Arc<Mutex<Box<dyn HexagonExecutionHelper>>>>,
    bytes_consumed: Option<u64>,

    pcodes: Option<Vec<Vec<Pcode>>>,
    ordering: SmallVec<[usize; 4]>,
    ordering_location: usize,
    first_packet: bool,
}

impl Hookable for HexagonPcodeBackend {
    fn add_hook(&mut self, hook: StyxHook) -> Result<HookToken, AddHookError> {
        self.internal_backend.add_hook(hook)
    }

    fn delete_hook(&mut self, token: HookToken) -> Result<(), DeleteHookError> {
        self.internal_backend.delete_hook(token)
    }
}

impl CpuBackend for HexagonPcodeBackend {
    fn read_register_raw(&mut self, reg: ArchRegister) -> Result<RegisterValue, ReadRegisterError> {
        self.internal_backend.read_register_raw(reg)
    }

    fn write_register_raw(
        &mut self,
        reg: ArchRegister,
        value: RegisterValue,
    ) -> Result<(), WriteRegisterError> {
        self.internal_backend.write_register_raw(reg, value)
    }

    fn architecture(&self) -> &dyn ArchitectureDef {
        self.internal_backend.architecture()
    }

    fn endian(&self) -> ArchEndian {
        self.internal_backend.endian()
    }

    fn execute(
        &mut self,
        mmu: &mut Mmu,
        ev: &mut EventController,
        count: u64,
    ) -> Result<ExecutionReport, UnknownError> {
        let mut total_instrs_executed = 0;
        // fetch a number of packets, then execute them
        for i in 0..count {
            trace!("pcket count is {i}");
            match self.fetch_decode_packet(mmu, ev)? {
                Ok(bytes) => {
                    self.bytes_consumed = Some(bytes);
                }
                Err(reason) => {
                    return Ok(ExecutionReport::new(reason, (i - 1) as u64));
                }
            }
            self.execution_regs_written = smallvec![];

            let pcodes = self.pcodes.take().unwrap();
            let ordering = self.ordering.clone();
            for i_instrs in ordering {
                let pcode_instrs = &pcodes[i_instrs];

                trace!("executing single instruction pcodes: {:?}", pcode_instrs);
                if let Err(reason) = self.execute_single(&pcode_instrs, mmu, ev)? {
                    return Ok(ExecutionReport::new(reason, i as u64));
                }
                total_instrs_executed += 1;
            }

            // We should only flush regs based on executed pcodes.
            trace!("end of packet, flushing registers...");
            let regs_flush_pcodes = self.flush_regs_pcode();

            if let Err(reason) = self.execute_single(&regs_flush_pcodes, mmu, ev)? {
                return Ok(ExecutionReport::new(reason, i as u64));
            }

            let execution_helper_outer = self.execution_helper.take().unwrap();
            {
                let mut execution_helper = execution_helper_outer.lock().unwrap();
                let next_pc = execution_helper.isa_pc() as u64 + self.bytes_consumed.unwrap();

                trace!(
                    "telling execution helper to bank move forward pc to {:x}",
                    next_pc
                );
                execution_helper.set_isa_pc(next_pc, &mut self.internal_backend);

                trace!("calling post packet execute hooks...");
                execution_helper.post_packet_execute(self);
            }
            self.execution_helper = Some(execution_helper_outer);
        }

        // Honestly, like, should this be instructions or packets?
        // Instructions might avoid a lot of pain
        Ok(ExecutionReport {
            exit_reason: TargetExitReason::InstructionCountComplete,
            instructions_executed: Some(total_instrs_executed as u64),
            last_packet_order: Some(self.ordering.clone()),
        })
    }

    fn stop(&mut self) {
        self.internal_backend.stop()
    }

    // TODO: fix this
    fn context_save(&mut self) -> Result<(), UnknownError> {
        self.internal_backend.context_save()
    }

    fn context_restore(&mut self) -> Result<(), UnknownError> {
        self.internal_backend.context_restore()
    }

    fn pc(&mut self) -> Result<u64, UnknownError> {
        let execution_helper_outer = self.execution_helper.take().unwrap();
        let pc = {
            let execution_helper = execution_helper_outer.lock().unwrap();
            execution_helper.isa_pc()
        };
        self.execution_helper = Some(execution_helper_outer);
        Ok(pc)
    }

    fn set_pc(&mut self, value: u64) -> Result<(), UnknownError> {
        let execution_helper_outer = self.execution_helper.take().unwrap();
        {
            let mut execution_helper = execution_helper_outer.lock().unwrap();
            execution_helper.set_isa_pc(value, &mut self.internal_backend);
        }
        self.execution_helper = Some(execution_helper_outer);
        Ok(())
    }
}

impl HexagonPcodeBackend {
    pub fn new_engine(
        _arch: Arch, // Kept to keep interface the same as unicorn
        arch_variant: impl Into<ArchVariant>,
        endian: ArchEndian,
    ) -> HexagonPcodeBackend {
        Self::new_engine_config(arch_variant, endian, &PcodeBackendConfiguration::default())
    }

    pub fn new_engine_config(
        arch_variant: impl Into<ArchVariant>,
        endian: ArchEndian,
        config: &PcodeBackendConfiguration,
    ) -> HexagonPcodeBackend {
        let mut internal_backend = PcodeBackend::new_engine_config(arch_variant, endian, config);
        let execution_helper: Arc<Mutex<Box<dyn HexagonExecutionHelper>>> = Arc::new(Mutex::new(
            Box::new(DefaultHexagonExecutionHelper::default()),
        ));

        let pc_manager = internal_backend.pc_manager.as_mut().unwrap();
        let pc_manager_down = pc_manager.downcast_mut::<PcManager>().unwrap();
        match pc_manager_down {
            PcManager::Hexagon(pc_manager) => {
                pc_manager.set_helper(execution_helper.clone());
            }
            _ => unreachable!(),
        }

        Self {
            internal_backend,
            saved_context_opts: SavedContextOpts::default(),
            regs_written: Vec::with_capacity(10),
            execution_regs_written: smallvec![],
            execution_helper: Some(execution_helper), // TODO: performance optimizations
            pcodes: Some(Vec::new()),
            ordering: SmallVec::new(),
            ordering_location: 0,
            bytes_consumed: None,
            first_packet: true,
        }
    }
    // Indicate when we should update the context reg
    // and what the new value should be
    pub fn update_context(&mut self, when: PacketLocation, what: ContextOption) {
        // TODO: what to do when Now is set outside of prefetch?
        // current functionality is to clear all unset now instructions out.
        self.saved_context_opts.update_context(when, what);
    }
    pub fn execute_single(
        &mut self,
        pcodes: &Vec<Pcode>,
        mmu: &mut Mmu,
        ev: &mut EventController,
    ) -> Result<Result<u64, TargetExitReason>, UnknownError> {
        // execute
        let mut i = 0;
        let total_pcodes = pcodes.len();

        let mut delayed_irqn: Option<i32> = None;

        while i < total_pcodes {
            let current_pcode = &pcodes[i];
            trace!(
                "Executing Pcode ({}/{total_pcodes}) {current_pcode:?}",
                i + 1
            );
            match execute_pcode::execute_pcode(
                current_pcode,
                &mut self.internal_backend,
                mmu,
                ev,
                &mut self.execution_regs_written,
            ) {
                PCodeStateChange::Fallthrough => i += 1,
                PCodeStateChange::DelayedInterrupt(irqn) => {
                    // interrupt will *probably* branch execution
                    let ret_value = delayed_irqn.replace(irqn);
                    assert!(ret_value.is_none(), "irqn already in delay interrupt slot");
                    i += 1;
                }
                PCodeStateChange::PCodeRelative(offset) => {
                    // for now assume math is good
                    let next_index = (i as i64 + offset) as usize;
                    trace!("Pcode state change relative jump {i}+{offset}={next_index}");
                    i = next_index;
                }
                PCodeStateChange::InstructionAbsolute(new_pc) => {
                    trace!("Pcode state change absolute jump new PC=0x{new_pc:X}");
                    self.set_pc(new_pc)?;
                    return Ok(Ok(i as u64)); // Don't increment PC, jump to next instruction
                }
                PCodeStateChange::Exception(irqn) => {
                    // exception occurred
                    // we should interrupt hook and rerun instruction
                    HookManager::trigger_interrupt_hook(&mut self.internal_backend, mmu, ev, irqn)?;
                    return Ok(Ok(self
                        .bytes_consumed
                        .expect("Couldn't get number of bytes consumed in packet")));
                    // Don't increment PC
                }
                PCodeStateChange::Exit(reason) => return Ok(Err(reason)),
            }
        }

        if let Some(irqn) = delayed_irqn {
            HookManager::trigger_interrupt_hook(&mut self.internal_backend, mmu, ev, irqn)?;
        }

        Ok(Ok(pcodes.len() as u64))
    }

    pub fn flush_regs_pcode(&self) -> Vec<Pcode> {
        let mut pcodes = vec![];
        for reg in &self.execution_regs_written {
            pcodes.push(Pcode {
                opcode: Opcode::Copy,
                inputs: smallvec![reg.clone()],
                output: {
                    let mut regc = reg.clone();
                    regc.offset -= DEST_REG_OFFSET;
                    Some(regc)
                },
            })
        }
        pcodes
    }

    /*pub fn execute_packets(
        &mut self,
        mmu: &mut Mmu,
        ev: &mut EventController,
        pkts: usize,
    ) -> Result<Result<u64, TargetExitReason>, UnknownError> {
        // Can't start executing packets after a packet has started or whatnot.
        for i in 0..pkts {
            self.fetch_decode_packet(mmu, ev);
            // We update this in case of an error?
            for i_pcode in &self.ordering {
                self.internal_backend
                    .execute_single(&mut self.pcodes[*i_pcode], mmu, ev)?;
                self.ordering_location += 1;
            }
            let mut execution_helper = self.execution_helper.take().unwrap();
            execution_helper.post_packet_execute(self);
            self.execution_helper = Some(execution_helper);
        }

        Ok(())
    }*/

    // this really should only be used for testing, it is extraorderingly inefficient
    pub(crate) fn ordering(&self) -> &SmallVec<[usize; 4]> {
        &self.ordering
    }

    fn internal_pc(&mut self) -> Result<u64, UnknownError> {
        trace!("fetching internal pc for next insn in fetch-decode packet");
        let execution_helper_outer = self.execution_helper.take().unwrap();
        let pc = {
            let execution_helper = execution_helper_outer.lock().unwrap();
            execution_helper.internal_pc()
        };
        self.execution_helper = Some(execution_helper_outer);
        Ok(pc)
    }

    fn fetch_decode_packet(
        &mut self,
        mmu: &mut Mmu,
        ev: &mut EventController,
    ) -> Result<Result<u64, TargetExitReason>, UnknownError> {
        assert_eq!(self.ordering_location, 0);

        self.regs_written.clear();
        let mut full_pcodes = vec![];

        let mut decode_state = PktState::PktEnded(None);
        let mut total_bytes_consumed = 0;
        let mut dotnew_total_insns = 0;
        let mut dotnew_regs_written = vec![];

        let mut pc = self.internal_pc().unwrap() as u32;

        loop {
            match decode_state {
                PktState::PktEnded(_) | PktState::PktStandalone(_) if total_bytes_consumed > 0 => {
                    break
                }
                _ => {}
            }
            // Pseudocode
            // TODO
            let execution_helper_outer = self.execution_helper.take().unwrap();
            let ctx_opts = {
                trace!("locking execution helper");
                let mut execution_helper = execution_helper_outer.lock().unwrap();
                trace!("locked execution helper");

                decode_state = execution_helper
                    .pre_insn_fetch(self, mmu, &decode_state, pc)
                    .map_err(|e| UnknownError::from_boxed(Box::new(e)))?;

                trace!("decode state has changed to {:?}", decode_state);

                if self.first_packet {
                    trace!("first packet in entire instruction sequence, handling");
                    execution_helper.first_pkt(self, pc);
                    self.first_packet = false;
                }

                // At this point, the context opts have "now" cleared, and everything else fine
                self.saved_context_opts.setup_context_opts(&decode_state);

                let res = match decode_state {
                    PktState::PktStarted(insns) => execution_helper.pkt_started(self, insns, pc),
                    PktState::InsidePacket(insns) => execution_helper.pkt_inside(self, insns),
                    PktState::PktEnded(insns) => execution_helper.pkt_ended(
                        self,
                        insns,
                        &dotnew_regs_written,
                        dotnew_total_insns,
                    ),
                    PktState::FirstDuplex(insns) => execution_helper.pkt_first_duplex(self, insns),
                    PktState::PktStartedFirstDuplex(insns) => Ok({
                        execution_helper
                            .pkt_first_duplex(self, insns)
                            .map_err(|e| UnknownError::from_boxed(Box::new(e)))?;
                        execution_helper
                            .pkt_started(self, insns, pc)
                            .map_err(|e| UnknownError::from_boxed(Box::new(e)))?;
                    }),
                    PktState::PktStandalone(insns) => Ok({
                        execution_helper
                            .pkt_started(self, insns, pc)
                            .map_err(|e| UnknownError::from_boxed(Box::new(e)))?;
                        // insns set to none as there will never be a dotnew in a
                        // standalone one-instruction packe t
                        execution_helper
                            .pkt_ended(self, None, &dotnew_regs_written, dotnew_total_insns)
                            .map_err(|e| UnknownError::from_boxed(Box::new(e)))?;
                    }),
                };
                res.map_err(|e| UnknownError::from_boxed(Box::new(e)))?;
                self.saved_context_opts.get_context_opts()
            };
            self.execution_helper = Some(execution_helper_outer);

            // Clear this now

            let helper = self
                .internal_backend
                .pcode_generator
                .helper
                .as_mut()
                .unwrap();

            helper.as_any_mut().downcast_mut::<Box<GeneratorHelper>>();

            match helper.as_mut() {
                GeneratorHelper::Hexagon(helper) => {
                    helper.update_context(ctx_opts);
                }
                _ => unreachable!(),
            }

            // TODO: optimize
            let mut pcodes = vec![];

            // TODO: Apply context options that were set across this. Because this uses the PcodeBackend behind
            // the scenes, we might need some sort of dummy generator helper/pc manager implementation that
            // that internally accesses/uses the current context opts
            //
            // Somehow we need to modify this stuff to take in the context options we care about.
            let bytes_consumed = fetch_pcode(&mut self.internal_backend, &mut pcodes, mmu, ev)?;
            trace!(
                "instruction consumed {} bytes and produced pcodes {:?}",
                bytes_consumed,
                pcodes
            );

            // Start common postfetch
            let is_immext = {
                // End packets do not matter
                match decode_state {
                    PktState::PktStarted(insn_data)
                    | PktState::InsidePacket(insn_data)
                    | PktState::PktStartedFirstDuplex(insn_data) => {
                        let iclass = parse_iclass(insn_data[0]);
                        iclass == 0b0000
                    }
                    PktState::PktStandalone(_)
                    | PktState::FirstDuplex(_)
                    | PktState::PktEnded(_) => false,
                }
            };

            let mut regs_in_insn = vec![];
            let mut first_general_reg = None;

            for pcode in &mut pcodes {
                let outvar = &pcode.output;
                if let Some(outvar_unwrap) = outvar {
                    if outvar_unwrap.space == SpaceName::Register {
                        trace!("pcode wrote register at {}", outvar_unwrap.offset);
                        regs_in_insn.push(outvar_unwrap.clone());

                        // Dotnew instructions require registers to be the postfix after R

                        let dotnew_regnum = outvar_unwrap.offset - DEST_REG_OFFSET;
                        if dotnew_regnum <= 28 * 4 {
                            first_general_reg = Some(dotnew_regnum / 4);
                        }
                    }
                }
            }

            if !is_immext {
                dotnew_total_insns += 1;
                dotnew_regs_written.push(first_general_reg);
            }

            full_pcodes.push(pcodes);
            // End common postfetch

            // TODO: change
            let execution_helper_outer = self.execution_helper.take().unwrap();
            {
                let mut execution_helper = execution_helper_outer.lock().unwrap();
                execution_helper.post_insn_fetch(bytes_consumed, self);

                pc += bytes_consumed as u32;
                trace!("advancing internal pc to {}", pc);
                execution_helper.set_internal_pc(pc as u64, &mut self.internal_backend)
            }
            self.execution_helper = Some(execution_helper_outer);
            self.saved_context_opts.advance_instr();
            self.regs_written.push(regs_in_insn);

            total_bytes_consumed += bytes_consumed;
        }

        // This hook may be useful for register flushing/banking

        let execution_helper_outer = self.execution_helper.take().unwrap();
        {
            let mut execution_helper = execution_helper_outer.lock().unwrap();
            execution_helper.post_packet_fetch(self);

            // TODO: remove this allocation, and turn this into an option that can be taken and replaced
            let mut ordering = smallvec![];
            execution_helper.sequence(self, &full_pcodes, &mut ordering);

            self.ordering_location = 0;
            self.ordering = ordering;
        }
        self.execution_helper = Some(execution_helper_outer);
        self.pcodes = Some(full_pcodes);

        Ok(Ok(total_bytes_consumed))
    }
}

pub trait HexagonExecutionHelper: derive_more::Debug + Send {
    // This is only called during execution, not decoding.
    fn isa_pc(&self) -> u64;
    fn internal_pc(&self) -> u64 {
        self.isa_pc()
    }
    fn set_isa_pc(&mut self, value: u64, backend: &mut PcodeBackend);
    fn set_internal_pc(&mut self, value: u64, backend: &mut PcodeBackend) {
        self.set_isa_pc(value, backend)
    }
    fn post_packet_execute(&mut self, _backend: &mut HexagonPcodeBackend) {}

    // During decoding
    fn pre_insn_fetch(
        &mut self,
        backend: &mut HexagonPcodeBackend,
        mmu: &mut Mmu,
        prev_state: &PktState,
        pc: u32,
    ) -> Result<PktState, GeneratePcodeError>;

    fn post_insn_fetch(&mut self, _bytes_consumed: u64, _backend: &mut HexagonPcodeBackend) {}

    fn post_packet_fetch(&mut self, backend: &mut HexagonPcodeBackend);
    fn pkt_started(
        &mut self,
        backend: &mut HexagonPcodeBackend,
        instrs: [u32; 4],
        pc: u32,
    ) -> Result<(), GeneratePcodeError>;
    fn pkt_inside(
        &mut self,
        backend: &mut HexagonPcodeBackend,
        instrs: [u32; 4],
    ) -> Result<(), GeneratePcodeError>;
    fn pkt_ended(
        &mut self,
        backend: &mut HexagonPcodeBackend,
        instr: Option<u32>,
        dotnew_regs_written: &Vec<Option<u64>>,
        dotnew_instructions: u32,
    ) -> Result<(), GeneratePcodeError>;
    fn pkt_first_duplex(
        &mut self,
        backend: &mut HexagonPcodeBackend,
        instrs: [u32; 4],
    ) -> Result<(), GeneratePcodeError>;
    fn first_pkt(&mut self, backend: &mut HexagonPcodeBackend, pc: u32);

    // Returns indices in the order of execution
    fn sequence(
        &mut self,
        backend: &mut HexagonPcodeBackend,
        pkt: &Vec<Vec<Pcode>>,
        ordering: &mut SmallVec<[usize; 4]>,
    );
}
