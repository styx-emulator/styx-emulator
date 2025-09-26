// SPDX-License-Identifier: BSD-2-Clause
mod arch_spec;
mod call_other;
mod execute_pcode;
mod get_pcode;
mod hooks;
mod memory;
mod pcode_gen;
mod register_manager;
mod types;

use crate::get_pcode::{fetch_pcode, is_branching_instruction};

use self::{
    hooks::HookManager,
    memory::{
        blob_store::BlobStore, hash_store::HashStore, sized_value::SizedValue, space::Space,
        space_manager::SpaceManager,
    },
    pcode_gen::GhidraPcodeGenerator,
    register_manager::RegisterManager,
};
use arch_spec::{build_arch_spec, ArchPcManager, PcManager};
use call_other::CallOtherManager;
use derivative::Derivative;
use log::trace;
use memory::{mmu_store::MmuSpace, space_manager::VarnodeError};
use pcode_gen::GeneratePcodeError;
use std::collections::{BTreeMap, HashMap};
use styx_cpu_type::{
    arch::{
        arm::SpecialArmRegister,
        backends::{ArchRegister, ArchVariant, SpecialArchRegister},
        ArchitectureDef, RegisterValue,
    },
    Arch, ArchEndian, TargetExitReason,
};
use styx_errors::{
    anyhow::{anyhow, Context},
    styx_cpu::StyxCpuBackendError,
    UnknownError,
};
use styx_pcode::pcode::{Pcode, SpaceName, VarnodeData};
use styx_processor::{
    core::{builder::BuildProcessorImplArgs, ExceptionBehavior},
    cpu::{CpuBackend, ExecutionReport, ReadRegisterError, WriteRegisterError},
    event_controller::{EventController, ExceptionNumber},
    memory::{MemoryOperation, MemoryType, Mmu},
    processor::ProcessorConfig,
};
use types::*;

/// vibe based default, should probably be more precisely set at some point in the future
///
/// increased from 20000 because ARM64 has too many registers
const REGISTER_SPACE_SIZE: usize = 80000;

#[derive(Debug, PartialEq)]
pub(crate) enum PCodeStateChange {
    /// Trigger interrupt at end of instruction execution. This is the proper method of triggering a
    /// synchronous interrupt e.g. `raise` or `svc`.
    DelayedInterrupt(ExceptionNumber),
    /// normal next instruction
    Fallthrough,
    /// a jump to a machine address
    InstructionAbsolute(u64),
    /// a relative jump to a pcode op within the current translation
    PCodeRelative(i64),
    /// Trigger interrupt as soon as possible. This is used for a TLB exception.
    Exception(i32),
    Exit(TargetExitReason),
}

struct MachineState {
    current_instruction_count: u64,
    max_instruction_count: u64,
}
impl MachineState {
    pub fn new(max_instruction_count: u64) -> Self {
        Self {
            current_instruction_count: 0,
            max_instruction_count,
        }
    }

    pub fn check_done(&self) -> Option<ExecutionReport> {
        if self.current_instruction_count >= self.max_instruction_count {
            return Some(ExecutionReport::new(
                TargetExitReason::InstructionCountComplete,
                self.current_instruction_count,
            ));
        }

        None
    }

    pub fn increment_instruction_count(&mut self) -> Option<ExecutionReport> {
        self.current_instruction_count += 1;
        self.check_done()
    }
}

/// Run on every "new basic block" meaning after every jump or at the start of execution.
fn handle_basic_block_hooks(
    initial_pc: u64,
    cpu: &mut PcodeBackend,
    mmu: &mut Mmu,
    ev: &mut EventController,
) -> Result<(), UnknownError> {
    let block_hook_count = cpu.hook_manager.block_hook_count()?;
    // Only run basic block hook finding if we have at least one block hook.
    if block_hook_count > 0 {
        let mut pcodes = Vec::with_capacity(16);

        // Maximum amount of bytes to search for the next branch.
        // This is necessary because it can continue the search through the whole address space.
        let max_search = 1000;
        let mut instruction_pc = initial_pc;

        // Does not matter if this is a branch instruction since it could be the beginning of
        // execution.
        let (_, bytes) = is_branching_instruction(cpu, &mut pcodes, initial_pc, mmu, ev);
        instruction_pc += bytes;

        let mut stop_search = false;
        while !stop_search {
            let (is_branch, bytes) =
                is_branching_instruction(cpu, &mut pcodes, instruction_pc, mmu, ev);

            // Stop search if we found a branch OR we've gone over our max search
            stop_search = is_branch || (instruction_pc - initial_pc) > max_search;
            instruction_pc += bytes
        }
        let total_block_size = instruction_pc - initial_pc;

        HookManager::trigger_block_hook(cpu, mmu, ev, initial_pc, total_block_size as u32)?;
    }
    Ok(())
}

/// The Pcode Cpu Backend
///
/// # Behaviors
///
/// ## Exceptions
///
/// Currently, the only exceptions implemented are the ones thrown by the
/// [TLB](styx_processor::memory::TlbImpl) (see
/// [TlbTranslateError::Exception](styx_processor::memory::TlbTranslateError::Exception)). When the
/// TLB indicates an exception, the rest of the pcodes in the instruction are not run and an
/// interrupt hook is triggered with the exception number given by the TLB. The Pc is not
/// incremented. It is expected that the interrupt hook handles the TLB exception as required by the
/// processor manual. With no intervention, the instruction will be run again, possibly throwing the
/// same TLB exception.
///
#[derive(Derivative)]
#[derivative(Debug)]
pub struct PcodeBackend {
    space_manager: SpaceManager,
    pcode_generator: GhidraPcodeGenerator,
    hook_manager: HookManager,
    /// Was there a stop requested through [CpuBackend::stop()]?
    ///
    /// This should be accessed through [Self::stop_request_check_and_reset()] to ensure it is
    /// cleared after handling.
    stop_requested: bool,
    #[derivative(Debug = "ignore")]
    arch_def: Box<dyn ArchitectureDef>,
    endian: ArchEndian,
    call_other_manager: CallOtherManager,
    register_manager: RegisterManager,
    pc_manager: Option<PcManager>,

    /// Was the last instruction a branch instruction?
    last_was_branch: bool,
    pcode_config: PcodeBackendConfiguration,

    // holds saved register state
    saved_context: BTreeMap<ArchRegister, RegisterValue>,
}

#[derive(Debug, Default, Clone)]
pub struct PcodeBackendConfiguration {
    pub register_read_hooks: bool,
    pub register_write_hooks: bool,
    pub exception: ExceptionBehavior,
}

impl ProcessorConfig for PcodeBackendConfiguration {}

impl From<&BuildProcessorImplArgs<'_>> for PcodeBackendConfiguration {
    fn from(value: &BuildProcessorImplArgs) -> Self {
        PcodeBackendConfiguration {
            exception: value.exception,
            ..Default::default()
        }
    }
}

trait HasConfig {
    fn config(&self) -> &PcodeBackendConfiguration;
}
impl HasConfig for PcodeBackend {
    fn config(&self) -> &PcodeBackendConfiguration {
        &self.pcode_config
    }
}

impl PcodeBackend {
    pub fn new_engine(
        _arch: Arch, // Kept to keep interface the same as unicorn
        arch_variant: impl Into<ArchVariant>,
        endian: ArchEndian,
    ) -> PcodeBackend {
        Self::new_engine_config(arch_variant, endian, &PcodeBackendConfiguration::default())
    }

    pub fn new_engine_config(
        arch_variant: impl Into<ArchVariant>,
        endian: ArchEndian,
        config: &PcodeBackendConfiguration,
    ) -> PcodeBackend {
        let arch_variant = arch_variant.into();

        let spec = build_arch_spec(&arch_variant, endian);
        let pcode_generator = spec.generator;

        let endian = pcode_generator.endian();

        let mut spaces: HashMap<_, _> = pcode_generator.spaces().collect();
        let default = spaces
            .remove(&pcode_generator.default_space())
            .expect("no default space in spaces");

        let default_space = MmuSpace::new(default);

        let mut space_manager = SpaceManager::new(
            pcode_generator.endian(),
            pcode_generator.default_space(),
            default_space,
        );
        for (space_name, space_info) in spaces {
            let space_memory = match space_name {
                // This is where we define the backing store for each of the spaces added to the
                // machine, based on their space name. The Ram space is already added above as the
                // default space and has the [StyxStore] memory storage and the
                // [SpaceName::Constant] store added by default.

                // Currently this allocates giant vectors which makes space reads/writes very fast
                // but also theoretically takes a lot of memory. However, Linux's paging system
                // allows us to allocate lots of memory without actually using any physical memory
                // until we access it.

                // This might blow if something writes to all addresses.
                SpaceName::Register => Some(BlobStore::new(REGISTER_SPACE_SIZE).unwrap().into()),
                SpaceName::Ram => None, // Default space already added with [StyxStore]
                SpaceName::Constant => None, // Constant space already added from SpaceManager
                SpaceName::Unique => Some(BlobStore::new(u32::MAX as usize).unwrap().into()),
                SpaceName::Other(_) => Some(HashStore::<1>::new().into()),
            };
            if let Some(space_memory) = space_memory {
                let new_space = Space::from_parts(space_info, space_memory);
                space_manager.insert_space(space_name, new_space).unwrap();
            }
        }

        // derive the styx architecture metadata from the enum passed in
        // the first `.into()` converts into the `ArchVariant`,
        // the second does the final conversion into an `ArchitectureDef`
        let arch_def: Box<dyn ArchitectureDef> = arch_variant.into();

        let hook_manager = HookManager::new();

        let call_other = spec.call_other;
        let register_manager = spec.register;
        Self {
            hook_manager,
            arch_def,
            // the backend does not have stop requested initially
            stop_requested: false,
            space_manager,
            pcode_generator,
            endian,
            call_other_manager: call_other,
            register_manager,
            pc_manager: Some(spec.pc_manager),
            last_was_branch: false,
            pcode_config: config.clone(),
            saved_context: BTreeMap::default(),
        }
    }

    /// Read a varnode from the pcode memory.
    ///
    /// Invalid spaces, incorrect offsets, and incorrect sizes will result in an Err.
    pub fn read(&self, varnode: &VarnodeData) -> Result<SizedValue, VarnodeError> {
        self.space_manager.read(varnode)
    }

    /// Write a varnode to the pcode memory.
    ///
    /// Invalid spaces, incorrect offsets, and incorrect sizes will result in an Err.
    pub fn write(&mut self, varnode: &VarnodeData, data: SizedValue) -> Result<(), VarnodeError> {
        self.space_manager.write(varnode, data)
    }

    /// Execute a single machine instruction.
    fn execute_single(
        &mut self,
        pcodes: &mut Vec<Pcode>,
        mmu: &mut Mmu,
        ev: &mut EventController,
    ) -> Result<Result<u64, TargetExitReason>, UnknownError> {
        // generate pcodes
        let mut pc_manager = self.pc_manager.take().unwrap();
        let pc_pre_fetch_res = pc_manager.pre_fetch(self);
        self.pc_manager = Some(pc_manager);
        if pc_pre_fetch_res.is_err() {
            return Err(anyhow!("pc overflowed in pcode backend during prefetch. you can modify the pc manager to wrap or prevent overflow if this is desired behavior"));
        }

        // fetch_pcode handles triggering hooks based on exception handler
        // Err(exit_reason) indicates an exception makes us pause so we should honor that
        let bytes_consumed = match fetch_pcode(self, pcodes, mmu, ev) {
            Ok(success) => success,
            Err(err) => match err {
                get_pcode::FetchPcodeError::TargetExit(target_exit_reason) => {
                    return Ok(Err(target_exit_reason))
                }
                get_pcode::FetchPcodeError::TlbException(irqn) => {
                    HookManager::trigger_interrupt_hook(self, mmu, ev, irqn)?;
                    return Ok(Ok(0));
                }
                get_pcode::FetchPcodeError::Other(error) => return Err(error),
            },
        };

        let mut pc_manager = self.pc_manager.take().unwrap();
        pc_manager.post_fetch(bytes_consumed, self);
        self.pc_manager = Some(pc_manager);

        trace!(
            "Instruction at 0x{:X} generated {} pcodes",
            self.pc()?,
            pcodes.len()
        );

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
            match execute_pcode::execute_pcode(current_pcode, self, mmu, ev) {
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
                    let mut pc_manager = self.pc_manager.take().unwrap();
                    pc_manager.set_internal_pc(new_pc, self);
                    self.pc_manager = Some(pc_manager);
                    return Ok(Ok(bytes_consumed)); // Don't increment PC, jump to next instruction
                }
                PCodeStateChange::Exception(irqn) => {
                    // exception occurred
                    // we should interrupt hook and rerun instruction
                    HookManager::trigger_interrupt_hook(self, mmu, ev, irqn)?;
                    return Ok(Ok(bytes_consumed)); // Don't increment PC
                }
                PCodeStateChange::Exit(reason) => return Ok(Err(reason)),
            }
        }
        let mut pc_manager = self.pc_manager.take().unwrap();
        let pc_post_execute_res = pc_manager.post_execute(bytes_consumed, self);
        self.pc_manager = Some(pc_manager);
        if pc_post_execute_res.is_err() {
            return Err(anyhow!("pc overflowed in pcode backend during post execute. you can modify the pc manager to wrap or prevent overflow if this is desired behavior"));
        }
        if let Some(irqn) = delayed_irqn {
            HookManager::trigger_interrupt_hook(self, mmu, ev, irqn)?;
        }

        Ok(Ok(bytes_consumed))
    }

    fn pre_execute_hooks(
        &mut self,
        mmu: &mut Mmu,
        ev: &mut EventController,
    ) -> Result<(), UnknownError> {
        // Trigger code hooks for this address
        // This is done before pcode generation allowing for the
        // current instruction to be modified in memory, not sure if this is correct behavior.
        let mut pc_manager = self.pc_manager.take().unwrap();
        pc_manager.pre_code_hook(self);
        self.pc_manager = Some(pc_manager);

        let pc = self.pc_manager.as_mut().unwrap().internal_pc();
        let physical_pc = mmu.translate_va(pc, MemoryOperation::Read, MemoryType::Code, self);
        if let Ok(physical_pc) = physical_pc {
            HookManager::trigger_code_hook(self, mmu, ev, physical_pc)?;
        } // no code hook if translate errors, we will catch then on instruction fetch
        Ok(())
    }

    fn pc_register(&self) -> styx_cpu_type::arch::CpuRegister {
        self.arch_def.registers().pc()
    }

    /// Clears stop_requested and returns the previous result.
    ///
    /// Use this instead of checking the raw value stop_requested to avoid bugs in forgetting to
    /// reset it.
    fn stop_request_check_and_reset(&mut self) -> bool {
        let res = self.stop_requested;
        self.stop_requested = false;
        res
    }
}

impl CpuBackend for PcodeBackend {
    fn read_register_raw(&mut self, reg: ArchRegister) -> Result<RegisterValue, ReadRegisterError> {
        let data = if reg == self.pc_register().variant() {
            SizedValue::from_u128(self.pc()? as u128, 4)
        } else {
            RegisterManager::read_register(self, reg)
                .map_err(|err| StyxCpuBackendError::GenericError(err.into()))
                .context("could not read_register_raw")?
        };
        if let ArchRegister::Special(SpecialArchRegister::Arm(SpecialArmRegister::CoProcessor(r))) =
            reg
        {
            Ok(r.with_value(data.to_u64().unwrap()).into())
        } else {
            Ok(data.try_into().with_context(|| "no")?)
        }
    }

    fn write_register_raw(
        &mut self,
        reg: ArchRegister,
        value: RegisterValue,
    ) -> Result<(), WriteRegisterError> {
        let sized_value: SizedValue = value.try_into().unwrap();

        let pc_reg_variant = self.pc_register().variant();
        if reg == pc_reg_variant {
            self.set_pc(sized_value.to_u64().with_context(|| "too big")?)?;
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

    fn execute(
        &mut self,
        mmu: &mut Mmu,
        event_controller: &mut EventController,
        count: u64,
    ) -> Result<ExecutionReport, UnknownError> {
        let mut state = MachineState::new(count);
        trace!("Starting pcode machine with max_count={count}");

        // Stop if requested in between ticks
        if self.stop_request_check_and_reset() {
            // self.is_stopped
            return Ok(ExecutionReport::new(TargetExitReason::HostStopRequest, 0));
        }
        self.stop_requested = false;
        let mut current_stop = state.check_done();
        let mut pcodes = Vec::with_capacity(20);

        self.last_was_branch = false;
        while current_stop.is_none() {
            // call code hooks, can change pc/execution path
            self.pre_execute_hooks(mmu, event_controller)
                .with_context(|| "pre execute hooks failed")
                .unwrap();

            // Stop if requested in code hook
            if self.stop_request_check_and_reset() {
                // self.is_stopped
                current_stop = Some(ExecutionReport::new(
                    TargetExitReason::HostStopRequest,
                    state.current_instruction_count,
                ));
                continue;
            }

            if self.last_was_branch {
                handle_basic_block_hooks(self.pc().unwrap(), self, mmu, event_controller)?;

                self.last_was_branch = false;
            }

            pcodes.clear();
            if let Err(reason) = self.execute_single(&mut pcodes, mmu, event_controller)? {
                return Ok(ExecutionReport::new(
                    reason,
                    state.current_instruction_count,
                ));
            }

            current_stop = state.increment_instruction_count();
            let stop_requested = self.stop_request_check_and_reset();
            trace!("current stop bool: {stop_requested}");
            current_stop = current_stop.or({
                if stop_requested {
                    Some(ExecutionReport::new(
                        TargetExitReason::HostStopRequest,
                        state.current_instruction_count,
                    ))
                } else {
                    None
                }
            })
        }
        let exit_reason = current_stop.unwrap();
        trace!("Exiting due to {exit_reason:?}");
        Ok(exit_reason)
    }

    fn pc(&mut self) -> Result<u64, UnknownError> {
        Ok(self.pc_manager.as_ref().unwrap().internal_pc())
    }

    fn set_pc(&mut self, value: u64) -> Result<(), UnknownError> {
        let mut pc_manager = self.pc_manager.take().unwrap();
        pc_manager.set_internal_pc(value, self);
        let isa_pc = SizedValue::from_u128(pc_manager.isa_pc() as u128, 4);
        self.pc_manager = Some(pc_manager);
        let pc_reg_variant = self.pc_register().variant();
        RegisterManager::write_register(self, pc_reg_variant, isa_pc)?;
        Ok(())
    }

    fn stop(&mut self) {
        self.stop_requested = true;
    }

    fn context_save(&mut self) -> Result<(), UnknownError> {
        self.saved_context.clear();

        for register in self.architecture().registers().registers() {
            // we need to do this because not every processor supports all of the valid registers defined by the architecture
            if let Ok(val) = self.read_register_raw(register.variant()) {
                self.saved_context.insert(register.variant(), val);
            }
        }

        Ok(())
    }

    fn context_restore(&mut self) -> Result<(), UnknownError> {
        if self.saved_context.is_empty() {
            return Err(anyhow!("attempting to restore from nothing"));
        }

        let context = std::mem::take(&mut self.saved_context);

        for register in context.keys() {
            self.write_register_raw(*register, *context.get(register).unwrap())?;
        }

        let _ = std::mem::replace(&mut self.saved_context, context);

        Ok(())
    }
}

#[cfg(test)]
#[cfg(feature = "arch_ppc")]
mod tests {
    use styx_cpu_type::arch::ppc32::{Ppc32Register, Ppc32Variants};
    use tap::Conv;

    use super::*;
    use styx_processor::{
        cpu::CpuBackendExt,
        hooks::{CoreHandle, Hookable, StyxHook},
        memory::helpers::WriteExt,
    };

    /// test a simple register write and read
    #[test]
    fn test_register_read_write() {
        let mut cpu =
            PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);

        cpu.write_register(Ppc32Register::R0, 10u32).unwrap();
        let val = cpu.read_register::<u32>(Ppc32Register::R0).unwrap();
        assert_eq!(val, 10);
    }

    /// test writing/reading to pc using set_pc()/pc() as well as read/write_register
    #[test]
    fn test_pc() {
        let mut cpu =
            PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);

        cpu.set_pc(10).unwrap();
        assert_eq!(cpu.pc().unwrap(), 10);
        let val = cpu.read_register::<u32>(Ppc32Register::Pc).unwrap();
        assert_eq!(val, 10);

        cpu.write_register(Ppc32Register::Pc, 20u32).unwrap();
        assert_eq!(cpu.pc().unwrap(), 20);
        let val = cpu.read_register::<u32>(Ppc32Register::Pc).unwrap();
        assert_eq!(val, 20);
    }

    #[test]
    fn test_save_restore_registers() {
        let mut cpu =
            PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);

        cpu.write_register(Ppc32Register::R3, 0x10_u32).unwrap();
        assert_eq!(
            cpu.read_register::<u32>(Ppc32Register::R3).unwrap(),
            0x10_u32
        );

        cpu.context_save().unwrap();

        cpu.write_register(Ppc32Register::R3, 0x20_u32).unwrap();
        assert_eq!(
            cpu.read_register::<u32>(Ppc32Register::R3).unwrap(),
            0x20_u32
        );

        cpu.context_restore().unwrap();

        assert_eq!(
            cpu.read_register::<u32>(Ppc32Register::R3).unwrap(),
            0x10_u32
        );
    }

    /// test writing/reading to pc using set_pc()/pc() as well as read/write_register
    #[test]
    fn test_exec() {
        styx_util::logging::init_logging();
        // objdump from example ppc program
        // notably load/store operations are omitted because sleigh uses dynamic pointers
        //   to represent memory spaces which change run to run.
        let objdump = r#"
             10c:	7c 3f 0b 78 	mr      r31,r1
             110:	3d 20 00 00 	lis     r9,0
             114:	39 40 00 00 	li      r10,0
             11c:	39 20 00 00 	li      r9,0
             124:	48 00 00 28 	b       14c <main+0x4c>
             128:	3d 20 00 00 	lis     r9,0
             134:	7d 4a 4a 14 	add     r10,r10,r9
             138:	3d 20 00 00 	lis     r9,0
             144:	39 29 00 01 	addi    r9,r9,1
             150:	2c 09 27 0f 	cmpwi   r9,9999
             154:	40 81 ff d4 	ble     128 <main+0x28>
             158:	3d 20 00 00 	lis     r9,0
             160:	7d 2f 4b 78 	mr      r15,r9
             164:	60 00 00 00 	nop
             168:	60 00 00 00 	nop
             16c:	4b ff ff fc 	b       168 <main+0x68>
             "#;

        let init_pc = 0x1000u64;
        // takes the objdump and extracts the binary from it
        let code = styx_util::parse_objdump(objdump).unwrap();

        let mut cpu =
            PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);

        cpu.set_pc(init_pc).unwrap();

        let mut mmu = Mmu::default();
        let mut ev = EventController::default();
        mmu.code().write(init_pc).bytes(&code).unwrap();

        cpu.write_register(Ppc32Register::R1, 0xdeadbeefu32)
            .unwrap();
        let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();

        assert_eq!(
            exit,
            ExecutionReport::new(TargetExitReason::InstructionCountComplete, 1)
        );

        let r31 = cpu.read_register::<u32>(Ppc32Register::R31).unwrap();
        assert_eq!(r31, 0xdeadbeef)
    }

    #[test]
    fn test_register_read_hook() {
        styx_util::logging::init_logging();
        let objdump = r#"
             10c:	7c 3f 0b 78 	mr      r31,r1
             "#;

        let init_pc = 0x1000u64;
        let code = styx_util::parse_objdump(objdump).unwrap();

        let mut cpu = PcodeBackend::new_engine_config(
            Ppc32Variants::Ppc405,
            ArchEndian::BigEndian,
            &PcodeBackendConfiguration {
                register_read_hooks: true,
                ..Default::default()
            },
        );

        cpu.set_pc(init_pc).unwrap();

        let mut mmu = Mmu::default();
        let mut ev = EventController::default();
        mmu.code().write(init_pc).bytes(&code).unwrap();

        cpu.write_register(Ppc32Register::R1, 0xdeadbeefu32)
            .unwrap();

        let register_read_hook = |_proc: CoreHandle, reg, data: &mut RegisterValue| {
            log::debug!("hit register read hook");
            assert_eq!(reg, Ppc32Register::R1.conv::<ArchRegister>());
            assert_eq!(data, &RegisterValue::u32(0xdeadbeef));
            *data = RegisterValue::u32(0xcafebabe);
            Ok(())
        };
        cpu.add_hook(StyxHook::RegisterRead(
            Ppc32Register::R1.into(),
            Box::new(register_read_hook),
        ))
        .unwrap();

        let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();

        assert_eq!(
            exit,
            ExecutionReport::new(TargetExitReason::InstructionCountComplete, 1)
        );

        let r31 = cpu.read_register::<u32>(Ppc32Register::R31).unwrap();
        assert_eq!(r31, 0xcafebabe)
    }

    #[test]
    fn test_register_write_hook() {
        styx_util::logging::init_logging();
        let objdump = r#"
             10c:	7c 3f 0b 78 	mr      r31,r1
             "#;

        let init_pc = 0x1000u64;
        let code = styx_util::parse_objdump(objdump).unwrap();

        let mut cpu = PcodeBackend::new_engine_config(
            Ppc32Variants::Ppc405,
            ArchEndian::BigEndian,
            &PcodeBackendConfiguration {
                register_write_hooks: true,
                ..Default::default()
            },
        );

        cpu.set_pc(init_pc).unwrap();

        let mut mmu = Mmu::default();
        let mut ev = EventController::default();
        mmu.code().write(init_pc).bytes(&code).unwrap();

        cpu.write_register(Ppc32Register::R1, 0xdeadbeefu32)
            .unwrap();

        let register_write_hook = |_proc: CoreHandle, reg, data: &RegisterValue| {
            log::debug!("hit register read hook");
            assert_eq!(reg, Ppc32Register::R31.conv::<ArchRegister>());
            assert_eq!(data, &RegisterValue::u32(0xdeadbeef));
            _proc
                .cpu
                .write_register(Ppc32Register::R2, 0xcafebabeu32)
                .unwrap();
            Ok(())
        };
        cpu.add_hook(StyxHook::RegisterWrite(
            Ppc32Register::R31.into(),
            Box::new(register_write_hook),
        ))
        .unwrap();

        let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();

        assert_eq!(
            exit,
            ExecutionReport::new(TargetExitReason::InstructionCountComplete, 1)
        );

        let r2 = cpu.read_register::<u32>(Ppc32Register::R2).unwrap();
        assert_eq!(r2, 0xcafebabe);
        let r31 = cpu.read_register::<u32>(Ppc32Register::R31).unwrap();
        assert_eq!(r31, 0xdeadbeef);
    }

    #[test]
    fn test_disable_register_hooks() {
        styx_util::logging::init_logging();
        let mut cpu =
            PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);

        let register_read_hook = |_proc: CoreHandle, _, _: &mut RegisterValue| Ok(());

        let register_write_hook = |_proc: CoreHandle, _, _: &RegisterValue| Ok(());

        let res = cpu.add_hook(StyxHook::RegisterRead(
            Ppc32Register::R1.into(),
            Box::new(register_read_hook),
        ));
        assert!(res.is_err());

        let res = cpu.add_hook(StyxHook::RegisterWrite(
            Ppc32Register::R1.into(),
            Box::new(register_write_hook),
        ));
        assert!(res.is_err());
    }
}

#[cfg(test)]
#[cfg(feature = "arch_arm")]
mod arm_tests {
    use keystone_engine::Keystone;
    use styx_cpu_type::{
        arch::arm::{ArmRegister, ArmVariants},
        Arch, ArchEndian, TargetExitReason,
    };
    use styx_processor::{
        cpu::{CpuBackend, CpuBackendExt, ExecutionReport},
        event_controller::EventController,
        hooks::{CoreHandle, Hookable, MemFaultData, Resolution, StyxHook},
        memory::{
            helpers::{ReadExt, WriteExt},
            MemoryPermissions, Mmu,
        },
    };
    use styx_sync::sync::{Arc, Mutex};

    use crate::PcodeBackend;

    /// Test fixture that uses ArmCortexA7 executor to test parts of the runtime
    struct TestMachine {
        proc: PcodeBackend,
        mmu: Mmu,
        ev: EventController,
        instruction_count: u32,
    }

    impl TestMachine {
        pub const fn start_address() -> u64 {
            0x1000
        }
        fn with_bytes(code: &[u8], instruction_count: u32) -> Self {
            let mut backend = PcodeBackend::new_engine(
                Arch::Arm,
                ArmVariants::ArmCortexM4,
                ArchEndian::LittleEndian,
            );
            let mut mmu = Mmu::default_region_store();
            let ev = EventController::default();
            mmu.memory_map(Self::start_address(), 0x1000, MemoryPermissions::all())
                .unwrap();

            // Write generated instructions to memory
            mmu.code().write(Self::start_address()).bytes(code).unwrap();
            // Start execution at our instructions
            backend
                .write_register(ArmRegister::Pc, Self::start_address() as u32)
                .unwrap();

            // get pc
            assert_eq!(
                Self::start_address(),
                backend.pc().unwrap(),
                "pc is not correct"
            );
            let pc_val = backend.read_register::<u32>(ArmRegister::Pc).unwrap();
            assert_eq!(
                Self::start_address(),
                pc_val as u64,
                "did not read pc correctly"
            );

            TestMachine {
                proc: backend,
                mmu,
                ev,
                instruction_count,
            }
        }
        fn with_code(instr: &str) -> Self {
            // Assemble instructions
            let ks = Keystone::new(keystone_engine::Arch::ARM, keystone_engine::Mode::THUMB)
                .expect("Could not initialize Keystone engine");
            let asm = ks
                .asm(instr.to_owned(), Self::start_address())
                .expect("Could not assemble");
            let code = asm.bytes;
            println!("generated code {code:X?}");
            let instruction_count = asm.stat_count;

            Self::with_bytes(&code, instruction_count)
        }

        fn run(&mut self) {
            let exit_reason = self
                .proc
                .execute(&mut self.mmu, &mut self.ev, self.instruction_count.into())
                .unwrap();

            assert_eq!(
                exit_reason,
                ExecutionReport::new(
                    TargetExitReason::InstructionCountComplete,
                    self.instruction_count.into()
                )
            );
        }

        fn run_with_reason(&mut self) -> ExecutionReport {
            self.proc
                .execute(&mut self.mmu, &mut self.ev, self.instruction_count.into())
                .unwrap()
        }

        fn run_unbounded(&mut self) {
            self.proc
                .execute(&mut self.mmu, &mut self.ev, 1000)
                .unwrap();
        }
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_simple() {
        styx_util::logging::init_logging();
        let mut machine = TestMachine::with_code("mov r0, #0xDE");

        let r0 = machine.proc.read_register::<u32>(ArmRegister::R0).unwrap();
        assert_eq!(r0, 0x00);
        println!("yo");

        machine.run();
        let r0 = machine.proc.read_register::<u32>(ArmRegister::R0).unwrap();
        assert_eq!(r0, 0xde);

        let pc = machine.proc.pc().unwrap();
        assert_eq!(pc, 0x1004);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_arm_pc() {
        let mut machine = TestMachine::with_code("movs r0, pc");
        assert_eq!(machine.instruction_count, 1);
        machine.run();
        let r0 = machine.proc.read_register::<u32>(ArmRegister::R0).unwrap() as u64;
        assert_eq!(r0, TestMachine::start_address() + 4);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_load() {
        let mut machine = TestMachine::with_code("movs r0, #0x00; ldr r1, [r0]");
        assert_eq!(machine.instruction_count, 2);

        machine
            .mmu
            .memory_map(0, 0x10, MemoryPermissions::READ)
            .unwrap();

        machine.mmu.sudo_data().write(0).le().u32(0x1337).unwrap();
        machine.run();
        let r1 = machine.proc.read_register::<u32>(ArmRegister::R1).unwrap();
        assert_eq!(r1, 0x00001337);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_memory_read_hook() {
        styx_util::logging::init_logging();
        let mut machine = TestMachine::with_code("movs r0, #0x00; ldr r1, [r0]");
        assert_eq!(machine.instruction_count, 2);

        machine
            .mmu
            .memory_map(0, 0x10, MemoryPermissions::RW)
            .unwrap();

        machine
            .proc
            .mem_read_hook(
                0x00,
                0x00,
                Box::new(move |cpu: CoreHandle, address, _size, _data: &mut [u8]| {
                    cpu.mmu.data().write(address).le().u32(0x1337).unwrap();
                    Ok(())
                }),
            )
            .unwrap();
        machine.run();
        let rtn = machine.mmu.data().read(0).le().u32().unwrap();
        assert_eq!(rtn, 0x1337);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_memory_write_hook() {
        let mut machine = TestMachine::with_code("movs r1, #0xDE; movs r0, #0x00; str r1, [r0]");
        assert_eq!(machine.instruction_count, 3);
        machine
            .mmu
            .memory_map(0, 0x10, MemoryPermissions::WRITE)
            .unwrap();

        let triggered = Arc::new(Mutex::new(false));
        {
            let triggered = triggered.clone();
            machine
                .proc
                .mem_write_hook(
                    0x00,
                    0x01,
                    Box::new(move |_a: CoreHandle, _b, _c, _data: &[u8]| {
                        *triggered.lock().unwrap() = true;
                        Ok(())
                    }),
                )
                .unwrap();
        }
        machine.run();
        assert!(*triggered.lock().unwrap());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_pcode_stack_pointers_todo() {
        let mut machine = TestMachine::with_bytes(
            &[
                0xde, 0x22, // movs r2, 0xde
                0x82, 0xF3, 0x08, 0x88, // msr msp, r2
                0x0d, 0x20, // movs r0, #13
                0x80, 0xf3, 0x09, 0x88, // msr psp, r0
            ],
            4, // 4 instructions
        );

        machine.run();
        assert_eq!(
            machine.proc.read_register::<u32>(ArmRegister::Sp).unwrap(),
            0xde
        );
        // TODO do psp
    }

    /// Test conditional branch
    ///
    /// The `ADDS R2, #1` at the beginning is to ensure the first instruction is only called once.
    /// If it wasn't there then the loop could jump to `loop-8` and still pass the test. This
    /// ensures the `BNE loop` jumps exactly to `loop`.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_loop_conditional_branch() {
        let mut machine = TestMachine::with_code(
            "
                ADDS R2, #1
            loop:
                SUBS R1, R1, #1
                BNE loop
                MOV R7, #1
                MOV R0, #0
                SWI 0",
        );

        machine
            .proc
            .intr_hook(Box::new(|backend: CoreHandle, _| {
                backend.cpu.stop();
                Ok(())
            }))
            .unwrap();
        machine.proc.write_register(ArmRegister::R1, 10u32).unwrap();
        println!("Running");
        machine.run_unbounded();
        println!("Done");

        let r1 = machine.proc.read_register::<u32>(ArmRegister::R1).unwrap();
        assert_eq!(r1, 0);
        let r2 = machine.proc.read_register::<u32>(ArmRegister::R2).unwrap();
        assert_eq!(r2, 1);
    }

    /// Test cpu.stop() inside a code hook.
    ///
    /// Correct behavior dictates that the instruction should not run
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_stop() {
        let mut machine = TestMachine::with_code("mov r0, #0xff; mov r0, #0xff; mov r0, #0xff");
        machine
            .proc
            .code_hook(
                0x1000,
                0x2000,
                Box::new(|backend: CoreHandle| {
                    backend.cpu.stop();
                    Ok(())
                }),
            )
            .unwrap();

        let exit_reason = machine.run_with_reason();
        assert_eq!(
            exit_reason,
            ExecutionReport::new(TargetExitReason::HostStopRequest, 0)
        );
        assert_eq!(
            machine.proc.read_register::<u32>(ArmRegister::R0).unwrap(),
            0x00
        );
        assert_eq!(
            machine.proc.read_register::<u32>(ArmRegister::Pc).unwrap(),
            0x1000
        );
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_branch() {
        let mut mmu = Mmu::default();
        let mut ev = EventController::default();
        let mut backend = PcodeBackend::new_engine(
            Arch::Arm,
            ArmVariants::ArmCortexA7,
            ArchEndian::LittleEndian,
        );

        // let region = MemoryRegion::new(0x0000, 0x100, MemoryPermissions::all()).unwrap();
        // backend.add_memory_region(region).unwrap();

        // let region = MemoryRegion::new(0x1000, 0x100, MemoryPermissions::all()).unwrap();
        // backend.add_memory_region(region).unwrap();

        // Assemble instructions
        let ks = Keystone::new(keystone_engine::Arch::ARM, keystone_engine::Mode::ARM)
            .expect("Could not initialize Keystone engine");
        let asm = ks
            .asm("b #0x10".to_string(), 0)
            .expect("Could not assemble");
        let code = asm.bytes;

        // backend.write_memory(0x1000, &code).unwrap();
        mmu.code().write(0x1000).bytes(&code).unwrap();
        println!("Starting..");
        backend.execute(&mut mmu, &mut ev, 1).unwrap();
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_cbranch() {
        let mut mmu = Mmu::default();
        let mut ev = EventController::default();
        let mut backend = PcodeBackend::new_engine(
            Arch::Arm,
            ArmVariants::ArmCortexA7,
            ArchEndian::LittleEndian,
        );

        // let region = MemoryRegion::new(0x0000, 0x100, MemoryPermissions::all()).unwrap();
        // backend.add_memory_region(region).unwrap();

        // let region = MemoryRegion::new(0x1000, 0x100, MemoryPermissions::all()).unwrap();
        // backend.add_memory_region(region).unwrap();

        // Assemble instructions
        let ks = Keystone::new(keystone_engine::Arch::ARM, keystone_engine::Mode::ARM)
            .expect("Could not initialize Keystone engine");
        let asm = ks
            .asm("beq #0x10".to_string(), 0)
            .expect("Could not assemble");
        let code = asm.bytes;

        mmu.code().write(0x1000).bytes(&code).unwrap();
        println!("Starting..");
        backend.execute(&mut mmu, &mut ev, 1).unwrap();
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_ind_branch() {
        let mut mmu = Mmu::default();
        let mut ev = EventController::default();
        let mut backend = PcodeBackend::new_engine(
            Arch::Arm,
            ArmVariants::ArmCortexA7,
            ArchEndian::LittleEndian,
        );

        // let region = MemoryRegion::new(0x0000, 0x100, MemoryPermissions::all()).unwrap();
        // backend.add_memory_region(region).unwrap();

        // let region = MemoryRegion::new(0x1000, 0x100, MemoryPermissions::all()).unwrap();
        // backend.add_memory_region(region).unwrap();

        // Assemble instructions
        let ks = Keystone::new(keystone_engine::Arch::ARM, keystone_engine::Mode::ARM)
            .expect("Could not initialize Keystone engine");
        let asm = ks.asm("bx lr".to_string(), 0).expect("Could not assemble");
        let code = asm.bytes;

        mmu.code().write(0x1000).bytes(&code).unwrap();
        println!("Starting..");
        backend.execute(&mut mmu, &mut ev, 1).unwrap();
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_store() {
        let mut mmu = Mmu::default();
        let mut ev = EventController::default();
        let mut backend = PcodeBackend::new_engine(
            Arch::Arm,
            ArmVariants::ArmCortexM4,
            ArchEndian::LittleEndian,
        );

        // let region = MemoryRegion::new(0x0000, 0x100, MemoryPermissions::all()).unwrap();
        // backend.add_memory_region(region).unwrap();

        // let region = MemoryRegion::new(0x1000, 0x100, MemoryPermissions::all()).unwrap();
        // backend.add_memory_region(region).unwrap();

        // Assemble instructions
        let ks = Keystone::new(keystone_engine::Arch::ARM, keystone_engine::Mode::THUMB)
            .expect("Could not initialize Keystone engine");
        let asm = ks
            .asm("str r3,[r2,#0x0]".to_string(), 0)
            .expect("Could not assemble");
        let code = asm.bytes;

        mmu.code().write(0x1000).bytes(&code).unwrap();
        backend.write_register(ArmRegister::Pc, 0x1000_u32).unwrap();
        println!("Starting..");
        backend.execute(&mut mmu, &mut ev, 1).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_pcode_protection_read_hooks() {
        // tests that the hook gets called when we read from a WO address
        let mut machine = TestMachine::with_code("movw r1, #0x9999; ldr r4, [r1];");

        // map in 0x9999 as write only
        machine
            .mmu
            .memory_map(0x9000, 0x1000, MemoryPermissions::WRITE)
            .unwrap();

        let cb = |proc: CoreHandle,
                  addr: u64,
                  size: u32,
                  perms: MemoryPermissions,
                  fault_data: MemFaultData| {
            println!("protection fault: 0x{addr:x} of size: {size}, type: {fault_data:?}");

            println!("region has permissions: {perms}");

            proc.cpu.write_register(ArmRegister::R2, 1u32).unwrap();

            Ok(Resolution::Fixed)
        };

        // insert hooks and collect tokens for removal later
        let token1 = machine
            .proc
            .add_hook(StyxHook::ProtectionFault((..).into(), Box::new(cb)))
            .unwrap();

        // both callback return `false`, so emulation should also exit
        // with an ProtectedMemoryRead error
        let exit_reason = machine.run_with_reason();

        assert_eq!(
            exit_reason,
            ExecutionReport::new(TargetExitReason::ProtectedMemoryRead, 1)
        );

        let end_pc = machine.proc.pc().unwrap();

        // basic assertions are correct
        assert_eq!(
            0x1004u64, end_pc,
            "Stopped at incorrect instruction: {end_pc:#x}",
        );
        assert_eq!(
            0x9999,
            machine.proc.read_register::<u32>(ArmRegister::R1).unwrap(),
            "r1 is incorrect immediate value",
        );

        // assertions to test that the hooks we successfully called
        assert_eq!(
            1,
            machine.proc.read_register::<u32>(ArmRegister::R2).unwrap(),
            "normal hook failed"
        );

        // removal of hooks is correct
        machine.proc.delete_hook(token1).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_pcode_protection_write_hooks() {
        // tests that the hook gets called when we write to a RO address
        let mut machine = TestMachine::with_code("movw r1, #0x9999;str r4, [r1];");

        // map in 0x9999 as read only
        machine
            .mmu
            .memory_map(0x9000, 0x1000, MemoryPermissions::READ)
            .unwrap();

        let cb = |proc: CoreHandle,
                  addr: u64,
                  size: u32,
                  perms: MemoryPermissions,
                  fault_data: MemFaultData| {
            println!("protection fault: 0x{addr:x} of size: {size}, type: {fault_data:?}");

            println!("region has permissions: {perms}");

            proc.cpu.write_register(ArmRegister::R2, 1u32).unwrap();

            Ok(Resolution::NotFixed)
        };

        // insert hooks and collect tokens for removal later
        let token1 = machine
            .proc
            .protection_fault_hook(0, u64::MAX, Box::new(cb))
            .unwrap();

        // both callback return `false`, so emulation should also exit
        // with an ProtectedMemoryWrite error
        let exit_reason = machine.run_with_reason();
        assert_eq!(
            exit_reason,
            ExecutionReport::new(TargetExitReason::ProtectedMemoryWrite, 1)
        );

        let end_pc = machine.proc.pc().unwrap();

        // basic assertions are correct
        assert_eq!(
            0x1004u64, end_pc,
            "Stopped at incorrect instruction: {end_pc:#x}",
        );
        assert_eq!(
            0x9999,
            machine.proc.read_register::<u32>(ArmRegister::R1).unwrap(),
            "r1 is incorrect immediate value",
        );

        // assertions to test that the hooks we successfully called
        assert_eq!(
            1,
            machine.proc.read_register::<u32>(ArmRegister::R2).unwrap(),
            "normal hook failed"
        );

        // removal of hooks is correct
        machine.proc.delete_hook(token1).unwrap();
    }
}

#[cfg(test)]
#[cfg(feature = "arch_bfin")]
mod blackfin_tests {
    use styx_cpu_type::arch::blackfin::{BlackfinRegister, BlackfinVariants};
    use styx_processor::{cpu::CpuBackendExt, memory::helpers::WriteExt};

    use super::*;

    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_blackfin_simple_set_and_decrement_r0() {
        let mut backend = PcodeBackend::new_engine(
            Arch::Blackfin,
            BlackfinVariants::Bf512,
            ArchEndian::LittleEndian,
        );
        let mut mmu = Mmu::default();
        let mut ev = EventController::default();

        let start_address = 0x1000;
        // mmu.memory_map(start_address, 0x1000, MemoryPermissions::all())
        //     .unwrap();

        let program = [0x28, 0x60, 0xF8, 0x67]; // R0 = 0x5; R0 += -0x1;
        mmu.data().write(start_address).bytes(&program).unwrap();
        backend.set_pc(start_address).unwrap();

        backend.execute(&mut mmu, &mut ev, 2).unwrap();

        assert_eq!(
            backend.read_register::<u32>(BlackfinRegister::R0).unwrap(),
            4,
            "R0 was not set correctly"
        )
    }
}

#[cfg(test)]
#[cfg(feature = "arch_mips32")]
mod mips32_tests {
    use keystone_engine::Keystone;
    use styx_cpu_type::arch::mips32::{Mips32MetaVariants, Mips32Register, Mips32Variants};
    use styx_processor::{cpu::CpuBackendExt, memory::helpers::WriteExt};
    use tap::Conv;

    use super::*;

    fn get_asm(instr: &str) -> Vec<u8> {
        let ks = Keystone::new(keystone_engine::Arch::MIPS, keystone_engine::Mode::MIPS32)
            .expect("Could not initialize Keystone engine");
        let asm = ks
            .asm(instr.to_owned(), 0x1000)
            .expect("Could not assemble");
        asm.bytes
    }

    #[test]
    fn test_mips32_simple_addition() {
        styx_util::logging::init_logging();

        let mut backend = PcodeBackend::new_engine(
            Arch::Mips32,
            Mips32Variants::Mips32r1Generic.conv::<Mips32MetaVariants>(),
            ArchEndian::LittleEndian,
        );
        let mut mmu = Mmu::default();
        let mut ev = EventController::default();

        let start_address: u32 = 0x1000;

        let src = r#"
            ori $t0, $zero, 1
            addi $t1, $zero, 2
            add $t2, $t0, $t1
        "#;
        let text = get_asm(src);

        mmu.data().write(start_address).bytes(&text).unwrap();
        backend
            .write_register(Mips32Register::Pc, start_address)
            .unwrap();

        backend.execute(&mut mmu, &mut ev, 3).unwrap();

        assert_eq!(
            backend.read_register::<u32>(Mips32Register::T0).unwrap(),
            1,
            "T0 was not set correctly"
        );
        assert_eq!(
            backend.read_register::<u32>(Mips32Register::T1).unwrap(),
            2,
            "T1 was not set correctly"
        );
        assert_eq!(
            backend.read_register::<u32>(Mips32Register::T2).unwrap(),
            3,
            "T2 was not set correctly (addition failed?)"
        );
    }
}
