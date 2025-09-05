// SPDX-License-Identifier: BSD-2-Clause
use std::collections::BTreeMap;

use anyhow::anyhow;
use execution_helper::DefaultHexagonExecutionHelper;
use log::trace;
pub use saved_context_opts::SavedContextOpts;
use smallvec::{smallvec, SmallVec};
use styx_cpu_type::{
    arch::{
        backends::{ArchRegister, ArchVariant},
        hexagon::HexagonRegister,
        ArchitectureDef, RegisterValue,
    },
    Arch, ArchEndian, TargetExitReason,
};
use styx_errors::{
    anyhow::{self, Context},
    styx_cpu::StyxCpuBackendError,
    UnknownError,
};
use styx_pcode::pcode::{Opcode, Pcode, SpaceName, VarnodeData};
use styx_pcode_translator::ContextOption;
use styx_processor::{
    cpu::{CpuBackend, ExecutionReport, ReadRegisterError, WriteRegisterError},
    event_controller::EventController,
    hooks::{AddHookError, DeleteHookError, HookToken, Hookable, StyxHook},
    memory::Mmu,
};
use tap::TryConv;
use thiserror::Error;

use crate::{
    arch_spec::hexagon::{parse_iclass, pkt_semantics::DEST_REG_OFFSET},
    backend_helper::BackendHelper,
    get_pcode::{FetchPcodeError, GetPcodeError, PcodeFetchException},
    pcode_gen::GeneratePcodeError,
    MachineState, PcodeBackendConfiguration,
};
use crate::{
    arch_spec::hexagon_build_arch_spec,
    backend_helper,
    call_other::CallOtherManager,
    get_pcode::{get_pcode_at_address, handle_pcode_exception},
    hooks::{HasHookManager, HookManager},
    memory::{
        sized_value::SizedValue,
        space_manager::{HasSpaceManager, SpaceManager},
    },
    pcode_gen::HasPcodeGenerator,
    register_manager::{HasRegisterManager, RegisterCallbackCpu},
    GhidraPcodeGenerator, HasConfig, RegisterManager, MAX_PACKET_SIZE,
};
use crate::{execute_pcode, ArchPcManager};
use crate::{PCodeStateChange, DEFAULT_REG_ALLOCATION};
use derive_more::Debug;

mod decode_info;
mod execution_helper;

mod saved_context_opts;

#[derive(Error, Debug)]
enum HexagonFetchDecodeError {
    #[error(transparent)]
    GetPcodeError(#[from] GetPcodeError),
    #[error(transparent)]
    Other(#[from] UnknownError),
}

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

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum OutputRegisterType {
    Predicate(u64, usize),
    General(u64),
    None,
}

enum HexagonSingleInstructionAction {
    DelayedInterrupt(i32),
    PcChange(u64),
    Rerun,
    None,
}

// We need an enum dispatch before we start using generics for dyn ExecutionHelper

#[derive(Debug)]
pub struct HexagonPcodeBackend {
    // These shared states are not local to a function to avoid
    // expensive re-allocations. we could maybe move to a smallvec
    // to get rid of this, but if we ever re-allocate these vectors to be larger
    // we can "use" this larger allocation later if needed.
    saved_context_opts: SavedContextOpts,
    regs_written: Vec<Vec<VarnodeData>>,

    execution_helper: Option<DefaultHexagonExecutionHelper>,

    // This state is for any hooks that need to set up edge case stuff for the very first packet that executes.
    first_packet: bool,

    // State required for execution
    pcode_config: PcodeBackendConfiguration,
    endian: ArchEndian,
    space_manager: SpaceManager,
    #[debug(skip)]
    arch_def: Box<dyn ArchitectureDef>,
    hook_manager: HookManager,
    register_manager: RegisterManager<Self>,
    pcode_generator: GhidraPcodeGenerator<Self>,
    stop_requested: bool,
    last_was_branch: bool,
    call_other_manager: Option<CallOtherManager<Self>>,

    // State for context saved/restored
    saved_reg_context: BTreeMap<ArchRegister, RegisterValue>,
    saved_execution_helper: Option<DefaultHexagonExecutionHelper>,
}

impl Hookable for HexagonPcodeBackend {
    fn add_hook(&mut self, hook: StyxHook) -> Result<HookToken, AddHookError> {
        self.hook_manager.add_hook(&self.pcode_config, hook)
    }

    fn delete_hook(&mut self, token: HookToken) -> Result<(), DeleteHookError> {
        self.hook_manager.delete_hook(token)
    }
}

impl HasSpaceManager for HexagonPcodeBackend {
    fn space_manager(&mut self) -> &mut SpaceManager {
        &mut self.space_manager
    }

    fn read(
        &self,
        varnode: &VarnodeData,
    ) -> Result<SizedValue, crate::memory::space_manager::VarnodeError> {
        self.space_manager.read(varnode)
    }

    fn write(
        &mut self,
        varnode: &VarnodeData,
        data: SizedValue,
    ) -> Result<(), crate::memory::space_manager::VarnodeError> {
        self.space_manager.write(varnode, data)
    }
}

impl HasPcodeGenerator for HexagonPcodeBackend {
    type InnerCpuBackend = HexagonPcodeBackend;

    fn pcode_generator_mut(&mut self) -> &mut GhidraPcodeGenerator<Self::InnerCpuBackend> {
        &mut self.pcode_generator
    }

    fn pcode_generator(&self) -> &GhidraPcodeGenerator<Self::InnerCpuBackend> {
        &self.pcode_generator
    }
}

impl HasHookManager for HexagonPcodeBackend {
    fn hook_manager(&mut self) -> &mut HookManager {
        &mut self.hook_manager
    }
}

impl HasRegisterManager for HexagonPcodeBackend {
    type InnerCpuBackend = HexagonPcodeBackend;

    fn register_manager(&mut self) -> &mut RegisterManager<Self::InnerCpuBackend> {
        &mut self.register_manager
    }
}

impl HasConfig for HexagonPcodeBackend {
    fn config(&self) -> &PcodeBackendConfiguration {
        &self.pcode_config
    }
}

impl RegisterCallbackCpu<HexagonPcodeBackend> for HexagonPcodeBackend {
    fn borrow_space_gen(
        &mut self,
    ) -> (
        &mut SpaceManager,
        &mut crate::GhidraPcodeGenerator<HexagonPcodeBackend>,
    ) {
        (&mut self.space_manager, &mut self.pcode_generator)
    }
}

impl BackendHelper<(u64, SmallVec<[usize; MAX_PACKET_SIZE]>), Vec<Pcode>> for HexagonPcodeBackend {
    fn pre_execute_hooks(
        &mut self,
        mmu: &mut Mmu,
        ev: &mut EventController,
    ) -> Result<(), UnknownError> {
        let pc = self.pc()?;
        backend_helper::pre_execute_hooks(self, pc, mmu, ev)
    }

    fn stop_requested(&self) -> bool {
        self.stop_requested
    }

    fn set_stop_requested(&mut self, stop_requested: bool) {
        self.stop_requested = stop_requested;
    }

    /// Execute a single packet. Returns number of instructions executed and the ordering of the packet (used for execution report)
    fn execute_single(
        &mut self,
        pcodes: &mut Vec<Vec<Pcode>>,
        mmu: &mut Mmu,
        ev: &mut EventController,
    ) -> Result<Result<(u64, SmallVec<[usize; MAX_PACKET_SIZE]>), TargetExitReason>, UnknownError>
    {
        let mut branched_pc: Option<u64> = None;
        let mut delayed_irqn: Option<i32> = None;
        let mut total_instrs_executed = 0;
        let mut execution_regs_written: SmallVec<[VarnodeData; DEFAULT_REG_ALLOCATION]> =
            smallvec![];

        let (bytes_consumed, ordering) = match self.fetch_decode_packet(pcodes, mmu, ev) {
            Ok(data) => match data {
                Ok(data) => data,
                Err(exit_reason) => return Ok(Err(exit_reason)),
            },
            // Try exactly once more, which is the same functionality as in
            // fetch_pcode
            Err(HexagonFetchDecodeError::GetPcodeError(result_err)) => {
                trace!("trying to get pcode again after a GetPcodeError");
                // Try one more time before giving up
                // Note: the PC could get set here, and we should NOT be
                // banking if this happens

                // This may overwrite the PC, but that's fine.
                let (target_exit_reason, did_fix) =
                    handle_pcode_exception(self, mmu, ev, result_err)?;

                trace!("did_fix: {did_fix:?}");

                if did_fix.fixed() {
                    match self.fetch_decode_packet(pcodes, mmu, ev)? {
                        Ok(bytes_consumed) => bytes_consumed,
                        Err(exit_reason) => {
                            return Ok(Err(exit_reason));
                        }
                    }
                } else {
                    return Ok(Err(target_exit_reason));
                }
            }
            Err(HexagonFetchDecodeError::Other(e)) => return Err(e),
        };

        for i_instrs in &ordering {
            let pcode_instrs = &pcodes[*i_instrs];

            trace!("executing single instruction pcodes: {pcode_instrs:?}");
            // this should actually do the fetching for each individual packet.
            // TODO: move everything that happens within one one execution. call this function something else,
            // like execute_packet_pcodes or something?
            match self.execute_single_instr(
                pcode_instrs,
                mmu,
                ev,
                &mut execution_regs_written,
                bytes_consumed,
            )? {
                Ok(HexagonSingleInstructionAction::DelayedInterrupt(irqn)) => {
                    delayed_irqn = Some(irqn);
                }
                Ok(HexagonSingleInstructionAction::Rerun) => {
                    todo!()
                }

                // Setting it only once when it's none allows for the first branch to be taken,
                // as required by double jumps
                Ok(HexagonSingleInstructionAction::PcChange(pc)) if branched_pc.is_none() => {
                    branched_pc = Some(pc)
                }
                Err(e) => return Ok(Err(e)),
                _ => {}
            }
            total_instrs_executed += 1;
        }

        // We should only flush regs based on executed pcodes.
        trace!("end of packet, flushing registers...");
        let regs_flush_pcodes = Self::flush_regs_pcode(&execution_regs_written);

        // NOTE: to my knowledge, this won't ever cause an interrupt??
        match self.execute_single_instr(
            &regs_flush_pcodes,
            mmu,
            ev,
            &mut execution_regs_written,
            bytes_consumed,
        )? {
            // Only handle if there was actually an IRQ request
            Ok(HexagonSingleInstructionAction::DelayedInterrupt(irqn)) => {
                delayed_irqn = Some(irqn);
            }
            Err(reason) => return Ok(Err(reason)),
            _ => {}
        }

        let mut execution_helper_outer = self.execution_helper.take().unwrap();
        {
            let next_pc = match branched_pc {
                Some(pc) => pc,
                None => execution_helper_outer.isa_pc() + bytes_consumed,
            };

            trace!("telling execution helper to bank move forward pc to {next_pc:x}");
            execution_helper_outer.set_isa_pc(next_pc, self);

            trace!("calling post packet execute hooks...");
            execution_helper_outer.post_packet_execute(self);
        }
        self.execution_helper = Some(execution_helper_outer);

        if let Some(irqn) = delayed_irqn {
            HookManager::trigger_interrupt_hook(self, mmu, ev, irqn)?;
        }

        Ok(Ok((total_instrs_executed, ordering)))
    }

    fn set_last_was_branch(&mut self, last_was_branch: bool) {
        self.last_was_branch = last_was_branch;
    }

    fn last_was_branch(&mut self) -> bool {
        self.last_was_branch
    }

    fn find_first_basic_block(
        &mut self,
        mmu: &mut Mmu,
        ev: &mut EventController,
        initial_pc: u64,
    ) -> u64 {
        unimplemented!()
    }
}

impl CpuBackend for HexagonPcodeBackend {
    fn read_register_raw(&mut self, reg: ArchRegister) -> Result<RegisterValue, ReadRegisterError> {
        let data = if reg == self.pc_register().variant() {
            SizedValue::from_u128(self.pc()? as u128, 4)
        } else {
            RegisterManager::read_register(self, reg)
                .map_err(|err| StyxCpuBackendError::GenericError(err.into()))
                .context("could not read_register_raw")?
        };
        Ok(data.try_into().with_context(|| "no")?)
    }

    fn write_register_raw(
        &mut self,
        reg: ArchRegister,
        value: RegisterValue,
    ) -> Result<(), WriteRegisterError> {
        let sized_value: SizedValue = value.try_into().unwrap();

        let pc_reg_variant = self.pc_register().variant();
        let pc_reg_pair_variant = HexagonRegister::C9C8.register().variant();

        if reg == pc_reg_variant {
            self.set_pc(sized_value.to_u64().with_context(|| "too big")?)?;
        } else if reg == pc_reg_pair_variant {
            // C9 is PC (hi 4 bytes), C8 is USR (lo 4 bytes)
            let val = sized_value
                .to_u64()
                .with_context(|| &"regpair should be (at least) 64 bits")?;

            let hi = (val >> 32) & 0xffffffff;
            let lo = (val & 0xffffffff) as u32;

            self.set_pc(hi)?;
            RegisterManager::write_register(
                self,
                HexagonRegister::Usr.into(),
                lo.try_into()
                    .with_context(|| &"couldn't turn c8 lo value into sizedvalue")?,
            )
            .with_context(|| "could not write_register_raw")?;
        } else {
            RegisterManager::write_register(self, reg, sized_value)
                .with_context(|| "could not write_register_raw")?;
        }

        Ok(())
    }

    fn architecture(&self) -> &dyn ArchitectureDef {
        self.arch_def.as_ref()
    }

    fn endian(&self) -> ArchEndian {
        self.endian
    }

    fn stop(&mut self) {
        self.stop_requested = true;
    }
    fn execute(
        &mut self,
        mmu: &mut Mmu,
        event_controller: &mut EventController,
        count: u64,
    ) -> Result<ExecutionReport, UnknownError> {
        self.execute_helper(mmu, event_controller, count)
            .map(|mut i| {
                i.1.last_packet_order = Some(i.0.unwrap().1);
                i.1
            })
    }

    // TODO: fix this
    fn context_save(&mut self) -> Result<(), UnknownError> {
        self.saved_reg_context.clear();

        for register in self.architecture().registers().registers() {
            // we need to do this because not every processor supports all of the valid registers defined by the architecture
            if let Ok(val) = self.read_register_raw(register.variant()) {
                self.saved_reg_context.insert(register.variant(), val);
            }
        }

        self.saved_execution_helper = self.execution_helper.clone();

        Ok(())
    }

    fn context_restore(&mut self) -> Result<(), UnknownError> {
        if self.saved_reg_context.is_empty() {
            return Err(anyhow!("attempting to restore from nothing"));
        }

        let reg_context = std::mem::take(&mut self.saved_reg_context);

        for register in reg_context.keys() {
            self.write_register_raw(*register, *reg_context.get(register).unwrap())?;
        }

        let _ = std::mem::replace(&mut self.saved_reg_context, reg_context);

        self.execution_helper = self.saved_execution_helper.clone();

        Ok(())
    }

    fn pc(&mut self) -> Result<u64, UnknownError> {
        Ok(self.execution_helper.as_ref().unwrap().isa_pc())
    }

    fn set_pc(&mut self, value: u64) -> Result<(), UnknownError> {
        let mut helper = self.execution_helper.take().unwrap();
        helper.set_isa_pc(value, self);
        self.execution_helper = Some(helper);

        Ok(())
    }
}

impl HexagonPcodeBackend {
    fn stop_request_check_and_reset(&mut self) -> bool {
        let res = self.stop_requested;
        self.stop_requested = false;
        res
    }

    fn pc_register(&self) -> styx_cpu_type::arch::CpuRegister {
        self.arch_def.registers().pc()
    }

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
        let arch_variant = arch_variant.into();

        let spec = hexagon_build_arch_spec(&arch_variant, endian);
        let pcode_generator = spec.generator;

        let endian = pcode_generator.endian();
        let space_manager = backend_helper::build_space_manager(&pcode_generator);

        let arch_def: Box<dyn ArchitectureDef> = arch_variant.clone().into();

        let hook_manager = HookManager::new();

        let call_other = spec.call_other;
        let register_manager = spec.register;

        let execution_helper = DefaultHexagonExecutionHelper::default();

        Self {
            saved_context_opts: SavedContextOpts::default(),
            regs_written: Vec::with_capacity(10),
            saved_execution_helper: None,
            execution_helper: Some(execution_helper), // TODO: performance optimizations
            first_packet: true,
            space_manager,
            endian,
            arch_def,
            hook_manager,
            register_manager,
            pcode_generator,
            pcode_config: config.clone(),
            stop_requested: false,
            last_was_branch: false,
            call_other_manager: Some(call_other),
            saved_reg_context: BTreeMap::new(),
        }
    }
    /// Indicate when we should update the context reg
    /// and what the new value should be
    pub fn update_context(&mut self, when: PacketLocation, what: ContextOption) {
        // TODO: what to do when Now is set outside of prefetch?
        // current functionality is to clear all unset now instructions out.
        self.saved_context_opts.update_context(when, what);
    }

    /// Execute a single instruction
    pub fn execute_single_instr(
        &mut self,
        pcodes: &Vec<Pcode>,
        mmu: &mut Mmu,
        ev: &mut EventController,
        execution_regs_written: &mut SmallVec<[VarnodeData; DEFAULT_REG_ALLOCATION]>,
        bytes_consumed: u64,
    ) -> Result<Result<HexagonSingleInstructionAction, TargetExitReason>, UnknownError> {
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
            let pc = self.pc()?;

            let mut call_other = self.call_other_manager.take().unwrap();

            let execute_result = execute_pcode::execute_pcode(
                current_pcode,
                self,
                mmu,
                ev,
                &mut call_other,
                pc,
                execution_regs_written,
            );

            self.call_other_manager = Some(call_other);

            match execute_result {
                PCodeStateChange::Fallthrough => i += 1,
                PCodeStateChange::DelayedInterrupt(irqn) => {
                    // interrupt will *probably* branch execution
                    self.last_was_branch = true;
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
                    self.last_was_branch = true;
                    // self.set_pc(new_pc)?;
                    return Ok(Ok(HexagonSingleInstructionAction::PcChange(new_pc)));
                    // Don't increment PC, jump to next instruction
                }
                PCodeStateChange::Exception(irqn) => {
                    // exception occurred
                    // we should interrupt hook and rerun instruction
                    HookManager::trigger_interrupt_hook(self, mmu, ev, irqn)?;
                    return Ok(Ok(HexagonSingleInstructionAction::Rerun));
                    // Don't increment PC
                }
                PCodeStateChange::Exit(reason) => return Ok(Err(reason)),
            }
        }

        // Delayed IRQ should run at the end of a packet, not at the end of
        // an instruction
        match delayed_irqn {
            Some(irqn) => Ok(Ok(HexagonSingleInstructionAction::DelayedInterrupt(irqn))),
            None => Ok(Ok(HexagonSingleInstructionAction::None)),
        }
    }

    pub fn flush_regs_pcode(
        execution_regs_written: &SmallVec<[VarnodeData; DEFAULT_REG_ALLOCATION]>,
    ) -> Vec<Pcode> {
        let mut pcodes = vec![];
        for reg in execution_regs_written {
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

    fn fetch_decode_packet(
        &mut self,
        full_pcodes: &mut Vec<Vec<Pcode>>,
        mmu: &mut Mmu,
        ev: &mut EventController,
    ) -> Result<
        Result<(u64, SmallVec<[usize; MAX_PACKET_SIZE]>), TargetExitReason>,
        HexagonFetchDecodeError,
    > {
        self.regs_written.clear();
        full_pcodes.clear();

        let mut ordering: SmallVec<[usize; 4]> = SmallVec::new();
        let mut decode_state = PktState::PktEnded(None);
        let mut total_bytes_consumed = 0;
        let mut dotnew_total_insns = 0;
        let mut dotnew_regs_written = vec![];
        let mut all_regs_written = vec![];

        let mut pc = self.pc().unwrap() as u32;

        loop {
            match decode_state {
                PktState::PktEnded(_) | PktState::PktStandalone(_) if total_bytes_consumed > 0 => {
                    break
                }
                _ => {}
            }
            let mut execution_helper = self.execution_helper.take().unwrap();
            let ctx_opts = {
                decode_state = execution_helper
                    .pre_insn_fetch(self, mmu, &decode_state, pc)
                    .map_err(|e| {
                        HexagonFetchDecodeError::Other(UnknownError::from_boxed(Box::new(e)))
                    })?;

                trace!("decode state has changed to {decode_state:?}");

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
                            .map_err(|e| {
                                HexagonFetchDecodeError::Other(UnknownError::from_boxed(Box::new(
                                    e,
                                )))
                            })?;
                        execution_helper.pkt_started(self, insns, pc).map_err(|e| {
                            HexagonFetchDecodeError::Other(UnknownError::from_boxed(Box::new(e)))
                        })?;
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
            self.execution_helper = Some(execution_helper);

            // TODO: optimize
            let mut pcodes = vec![];

            // TODO: Apply context options that were set across this. Because this uses the PcodeBackend behind
            // the scenes, we might need some sort of dummy generator helper/pc manager implementation that
            // that internally accesses/uses the current context opts
            //
            // Somehow we need to modify this stuff to take in the context options we care about.

            let bytes_consumed =
                get_pcode_at_address(self, pc as u64, &mut pcodes, &ctx_opts?, mmu, ev)?;

            trace!("instruction consumed {bytes_consumed} bytes and produced pcodes {pcodes:?}");

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
            let mut first_general_reg = OutputRegisterType::None;

            for (i, pcode) in pcodes.iter().enumerate() {
                let outvar = &pcode.output;
                if let Some(outvar_unwrap) = outvar {
                    if outvar_unwrap.space == SpaceName::Register {
                        trace!("pcode wrote register at {}", outvar_unwrap.offset);
                        regs_in_insn.push(outvar_unwrap.clone());

                        // Dotnew snstructions require registers to be the postfix after R

                        let dotnew_regnum = outvar_unwrap.offset - DEST_REG_OFFSET;
                        // Permit R* registers or P* registers
                        if dotnew_regnum <= 28 * 4 {
                            first_general_reg = OutputRegisterType::General(dotnew_regnum / 4);
                        } else if (0x94..=0x97).contains(&dotnew_regnum) {
                            first_general_reg =
                                OutputRegisterType::Predicate(dotnew_regnum - 0x94, i + 1);
                        }
                    }
                }
            }

            all_regs_written.push(first_general_reg.clone());

            if !is_immext {
                dotnew_total_insns += 1;
                dotnew_regs_written.push(first_general_reg);
            }

            full_pcodes.push(pcodes);
            // End common postfetch

            // TODO: change
            let mut execution_helper = self.execution_helper.take().unwrap();
            {
                execution_helper.post_insn_fetch(bytes_consumed, self);

                trace!("advancing fetch pc to {pc}");
                pc += bytes_consumed as u32;
            }
            self.execution_helper = Some(execution_helper);

            self.saved_context_opts.advance_instr();
            self.regs_written.push(regs_in_insn);

            total_bytes_consumed += bytes_consumed;
        }

        // This hook may be useful for register flushing/banking

        let mut execution_helper = self.execution_helper.take().unwrap();
        {
            execution_helper.post_packet_fetch(self);

            // TODO: remove this allocation, and turn this into an option that can be taken and replaced
            execution_helper.sequence(self, &full_pcodes, &mut ordering);

            // Now that sequencing is done, it is time to deal with predicate ANDing.
            //
            // If the current output reg is a predicate register,
            // and this register is also present in the all_regs_written, then
            // we are in a predicate AND situation
            let mut predicates_found = [false, false, false, false];
            for i in &ordering {
                let first_general_reg = &all_regs_written[*i];
                if let OutputRegisterType::Predicate(dotnew_regnum, ins_loc) = &first_general_reg {
                    trace!(
                        "all_regs_written {all_regs_written:?} first_general_reg {first_general_reg:?} predicates_found {predicates_found:?}"
                    );
                    // This dotnew value was already set.
                    if predicates_found[*dotnew_regnum as usize] {
                        trace!("Predicate anding situation detected at {i}!");
                        const UNIQ_LOC: u64 = 0x20000000u64;
                        // We must push this immediately after the instruction that outputs to the predicat,
                        // mainly because there are *fun* instructions like p0 = cmp.eq(...); if (p0.new) ...
                        // where the compare and jump happen in the same instruction

                        // Also, this kind of assumes that the predicate register is either 0x00 or 0xff, and
                        // nothing else.
                        full_pcodes[*i].insert(
                            *ins_loc,
                            Pcode {
                                opcode: Opcode::IntAnd,
                                inputs: smallvec![
                                    VarnodeData {
                                        space: SpaceName::Register,
                                        offset: DEST_REG_OFFSET + (*dotnew_regnum + 0x94),
                                        size: 1,
                                    },
                                    VarnodeData {
                                        space: SpaceName::Unique,
                                        offset: UNIQ_LOC,
                                        size: 1
                                    }
                                ],
                                output: Some(VarnodeData {
                                    space: SpaceName::Register,
                                    offset: DEST_REG_OFFSET + (*dotnew_regnum + 0x94),
                                    size: 1,
                                }),
                            },
                        );

                        // We are in a predicate anding situation, so now play with pcodes
                        full_pcodes[*i].insert(
                            0,
                            Pcode {
                                opcode: Opcode::Copy,
                                inputs: smallvec![VarnodeData {
                                    space: SpaceName::Register,
                                    offset: DEST_REG_OFFSET + (*dotnew_regnum + 0x94),
                                    size: 1
                                }],
                                // WARN: is there an issue here with the unique space somehow overlapping?
                                // WARN: is this too big?
                                output: Some(VarnodeData {
                                    space: SpaceName::Unique,
                                    offset: UNIQ_LOC,
                                    size: 1,
                                }),
                            },
                        );
                    }
                    // Predicate wasn't found, so indicate that we have found it
                    else {
                        trace!("marking predicate {} as found at {}", *dotnew_regnum, i);
                        predicates_found[*dotnew_regnum as usize] = true;
                    }
                }
            }
        }
        self.execution_helper = Some(execution_helper);

        Ok(Ok((total_bytes_consumed, ordering)))
    }
}

pub trait HexagonExecutionHelper: derive_more::Debug + Send {
    // This is only called during execution, not decoding.
    fn isa_pc(&self) -> u64;
    fn set_isa_pc(&mut self, value: u64, backend: &mut HexagonPcodeBackend);

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
        dotnew_regs_written: &Vec<OutputRegisterType>,
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
