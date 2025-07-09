// SPDX-License-Identifier: BSD-2-Clause
mod call_other;
pub mod cortex_a7;
pub mod cortex_a9;
pub mod cortex_m3;
pub mod cortex_m4;
mod helpers;
mod register;

use super::{
    pc_manager::{apply_difference, PcOverflow},
    ArchPcManager, ArchSpecBuilder, GeneratorHelp,
};
use crate::{arch_spec::ArchSpec, call_other::handlers::TraceCallOther, PcodeBackend};
use call_other::*;
use helpers::StackPointerManager;
use log::debug;
use register::*;
use std::str::FromStr;
use styx_cpu_type::{
    arch::{
        arm::{ArmMetaVariants, ArmRegister},
        backends::ArchVariant,
    },
    ArchEndian,
};
use styx_pcode::sla::SlaUserOps;
use styx_pcode_translator::{sla::Arm7LeUserOps, ContextOption};
use styx_processor::cpu::CpuBackendExt;
use styx_sync::sync::Arc;

pub fn arm_arch_spec(
    arch: &ArchVariant,
    variant: &ArmMetaVariants,
    endian: ArchEndian,
) -> ArchSpec {
    match endian {
        ArchEndian::LittleEndian => match variant {
            ArmMetaVariants::ArmCortexM3(_) => cortex_m3::build_le().build(arch),
            ArmMetaVariants::ArmCortexM4(_) => cortex_m4::build_le().build(arch),
            ArmMetaVariants::ArmCortexA7(_) => cortex_a7::build_le().build(arch),
            ArmMetaVariants::ArmCortexA9(_) => cortex_a9::build_le().build(arch),
            _ => unimplemented!("arm variant {variant:?} not supported by pcode backend"),
        },
        ArchEndian::BigEndian => match variant {
            ArmMetaVariants::ArmCortexA7(_) => cortex_a7::build_be().build(arch),
            ArmMetaVariants::ArmCortexA9(_) => cortex_a9::build_be().build(arch),
            ArmMetaVariants::ArmCortexM3(_) => cortex_m3::build_be().build(arch),
            ArmMetaVariants::ArmCortexM4(_) => cortex_m4::build_be().build(arch),
            _ => unimplemented!("arm variant {variant:?} not supported by pcode backend"),
        },
    }
}

fn armv7_common<T: SlaUserOps<UserOps: FromStr>>(spec: &mut ArchSpecBuilder<T>) {
    let call_other_manager = &mut spec.call_other_manager;
    let register_manager = &mut spec.register_manager;

    call_other_manager
        .add_handler_other_sla(Arm7LeUserOps::IsCurrentModePrivileged, IsPrivileged)
        .unwrap();
    let stack_pointer_manager = Arc::new(StackPointerManager::default());
    call_other_manager
        .add_handler_other_sla(Arm7LeUserOps::GetMainStackPointer, GetMainStackPointer)
        .unwrap();
    call_other_manager
        .add_handler_other_sla(
            Arm7LeUserOps::GetProcessStackPointer,
            GetProcessStackPointer {
                stack_pointer_manager: stack_pointer_manager.clone(),
            },
        )
        .unwrap();
    call_other_manager
        .add_handler_other_sla(Arm7LeUserOps::SetMainStackPointer, SetMainStackPointer)
        .unwrap();
    call_other_manager
        .add_handler_other_sla(
            Arm7LeUserOps::SetProcessStackPointer,
            SetProcessStackPointer {
                stack_pointer_manager: stack_pointer_manager.clone(),
            },
        )
        .unwrap();

    register_manager
        .add_handler(
            ArmRegister::Msp,
            MainStackPointerHandler {
                stack_pointer_manager: stack_pointer_manager.clone(),
            },
        )
        .unwrap();
    register_manager
        .add_handler(
            ArmRegister::Psp,
            ProcessStackPointerHandler {
                stack_pointer_manager: stack_pointer_manager.clone(),
            },
        )
        .unwrap();
    register_manager
        .add_handler(
            ArmRegister::Control,
            ControlHandler::new(stack_pointer_manager.clone()),
        )
        .unwrap();

    call_other_manager
        .add_handler_other_sla(Arm7LeUserOps::SetBasePriority, SetBasePriority)
        .unwrap();

    call_other_manager
        .add_handler_other_sla(Arm7LeUserOps::EnableIrQinterrupts, EnableIRQInterrupts)
        .unwrap();
    call_other_manager
        .add_handler_other_sla(Arm7LeUserOps::EnableFiQinterrupts, EnableFIQInterrupts)
        .unwrap();
    call_other_manager
        .add_handler_other_sla(Arm7LeUserOps::DisableIrQinterrupts, DisableIRQInterrupts)
        .unwrap();
    call_other_manager
        .add_handler_other_sla(Arm7LeUserOps::DisableFiQinterrupts, DisableFIQInterrupts)
        .unwrap();
    call_other_manager
        .add_handler_other_sla(
            Arm7LeUserOps::DataSynchronizationBarrier,
            TraceCallOther::new("DataSynchronizationBarrier called.".into()),
        )
        .unwrap();
    call_other_manager
        .add_handler_other_sla(
            Arm7LeUserOps::InstructionSynchronizationBarrier,
            TraceCallOther::new("InstructionSynchronizationBarrier called.".into()),
        )
        .unwrap();
    call_other_manager
        .add_handler_other_sla(Arm7LeUserOps::SoftwareInterrupt, SoftwareInterruptCallOther)
        .unwrap();

    register_manager
        .add_handler(ArmRegister::Apsr, ApsrHandler)
        .unwrap();

    register_manager
        .add_handler(ArmRegister::Basepri, BasePriorityHandler::default())
        .unwrap();
    register_manager
        .add_handler(ArmRegister::Primask, PriorityMaskRegister::default())
        .unwrap();
    register_manager
        .add_handler(ArmRegister::Faultmask, FaultMaskRegister::default())
        .unwrap();

    // floating point registers
    for x in 0..32 {
        let reg = ArmRegister::from_str(&format!("S{x}")).unwrap();
        register_manager
            .add_handler(reg, FloatingPointExtensionHandler::default())
            .unwrap();
    }
    register_manager
        .add_handler(ArmRegister::Fpscr, FloatingPointExtensionHandler::default())
        .unwrap();
}

fn armv7m_common<S>(spec: &mut ArchSpecBuilder<S>) {
    let register_manager = &mut spec.register_manager;

    register_manager
        .add_handler(ArmRegister::Xpsr, XpsrHandler)
        .unwrap();
    register_manager
        .add_handler(ArmRegister::Ipsr, Ipsr::default())
        .unwrap();
    register_manager
        .add_handler(ArmRegister::Epsr, Epsr)
        .unwrap();
}

fn armv7a_common<S>(spec: &mut ArchSpecBuilder<S>) {
    let register_manager = &mut spec.register_manager;
    register_manager
        .add_handler(ArmRegister::Cpsr, CpsrHandler)
        .unwrap();
}

/// Program Counter manager for the thumb-only ARM processors.
#[derive(Debug)]
pub struct ThumbPcManager {
    isa_pc: u64,
    internal_pc: u64,
}
impl ArchPcManager for ThumbPcManager {
    fn isa_pc(&self) -> u64 {
        self.isa_pc
    }

    fn internal_pc(&self) -> u64 {
        self.internal_pc
    }

    fn set_internal_pc(&mut self, value: u64, _backend: &mut PcodeBackend) {
        // i128 here is used so we don't overflow on cast
        let difference = (value as i128 - self.internal_pc as i128) & (!1);

        apply_difference(&mut self.internal_pc, difference);
        apply_difference(&mut self.isa_pc, difference);
    }

    fn set_isa_pc(&mut self, value: u64, _backend: &mut PcodeBackend) {
        // i128 here is used so we don't overflow on cast
        let difference = (value as i128 - self.isa_pc as i128) & (!1);

        apply_difference(&mut self.internal_pc, difference);
        apply_difference(&mut self.isa_pc, difference);
    }

    fn post_fetch(&mut self, bytes_consumed: u64, _backend: &mut PcodeBackend) {
        // ~technically~ wrapping is correct but if the pc wraps we're in trouble
        self.isa_pc += bytes_consumed;
    }
    fn post_execute(
        &mut self,
        bytes_consumed: u64,
        _backend: &mut PcodeBackend,
    ) -> Result<(), PcOverflow> {
        self.internal_pc = self
            .internal_pc
            .checked_add(bytes_consumed)
            .ok_or(PcOverflow)?;

        Ok(())
    }
}

impl Default for ThumbPcManager {
    fn default() -> Self {
        Self {
            isa_pc: (2 * 2), // +2 instructions, each instruction is 2 bytes in thumb mode
            internal_pc: 0,
        }
    }
}

/// Program Counter manager for Armv7-A processors.
///
/// Controls thumb mode base on bit 5 of the CPSR.
#[derive(Debug)]
pub struct StandardPcManager {
    isa_pc: u64,
    internal_pc: u64,
}
impl StandardPcManager {
    fn is_thumb_mode(&self, backend: &mut PcodeBackend) -> bool {
        let cpsr = backend.read_register::<u32>(ArmRegister::Cpsr).unwrap();
        // bit 5 contains thumb mode bit (1=thumb mode, 0=not thumb mode)
        ((cpsr >> 5) & 1) == 1
    }

    fn isa_pc_offset(&self, backend: &mut PcodeBackend) -> u64 {
        if self.is_thumb_mode(backend) {
            4 // +2 instructions, each instruction is 2 bytes in thumb mode
        } else {
            8 // +2 instructions, each instruction is 4 bytes in arm mode
        }
    }

    fn realign_isa_pc(&mut self, backend: &mut PcodeBackend) -> Result<(), PcOverflow> {
        self.isa_pc = self
            .internal_pc
            .checked_add(self.isa_pc_offset(backend))
            .ok_or(PcOverflow)?;
        Ok(())
    }
}
impl ArchPcManager for StandardPcManager {
    fn isa_pc(&self) -> u64 {
        self.isa_pc
    }

    fn internal_pc(&self) -> u64 {
        self.internal_pc
    }

    fn set_internal_pc(&mut self, value: u64, _backend: &mut PcodeBackend) {
        // i128 here is used so we don't overflow on cast
        let difference = (value as i128 - self.internal_pc as i128) & (!1);

        apply_difference(&mut self.internal_pc, difference);
        apply_difference(&mut self.isa_pc, difference);
    }

    fn set_isa_pc(&mut self, value: u64, _backend: &mut PcodeBackend) {
        // i128 here is used so we don't overflow on cast
        let difference = (value as i128 - self.isa_pc as i128) & (!1);

        apply_difference(&mut self.internal_pc, difference);
        apply_difference(&mut self.isa_pc, difference);
    }

    fn post_fetch(&mut self, bytes_consumed: u64, _backend: &mut PcodeBackend) {
        self.isa_pc += bytes_consumed;
    }
    fn post_execute(
        &mut self,
        bytes_consumed: u64,
        backend: &mut PcodeBackend,
    ) -> Result<(), PcOverflow> {
        self.internal_pc = self
            .internal_pc
            .checked_add(bytes_consumed)
            .ok_or(PcOverflow)?;

        // realign to thumb mode
        self.isa_pc = self
            .internal_pc
            .checked_add(self.isa_pc_offset(backend))
            .ok_or(PcOverflow)?;

        Ok(())
    }

    fn pre_fetch(&mut self, backend: &mut PcodeBackend) -> Result<(), PcOverflow> {
        // realign to thumb mode in case code hook changed thumb mode
        self.realign_isa_pc(backend)
    }
}

impl Default for StandardPcManager {
    fn default() -> Self {
        Self {
            isa_pc: 8, // +2 instructions, each instruction is 4 bytes in arm mode
            internal_pc: 0,
        }
    }
}

/// Simple Arm instruction set/Thumb instruction set enum
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum ArmCpuMode {
    Arm,
    Thumb,
}
impl ArmCpuMode {
    /// Parses CPSR register into thumb/arm mode
    fn from_cpsr(cpsr: u32) -> Self {
        let is_thumb = ((cpsr >> 5) & 1) == 1;
        if is_thumb {
            Self::Thumb
        } else {
            Self::Arm
        }
    }

    fn is_thumb(self) -> bool {
        self == ArmCpuMode::Thumb
    }
}

/// Thumb mode switching for Armv7-A processors,
///
/// Thumb mode bit is bit 5 of the CPSR register.
#[derive(Debug, Default)]
pub struct StandardGeneratorHelper {
    /// Stores the previous cpu mode, [None] at start of running when no mode is stored.
    previous_mode: Option<ArmCpuMode>,
}

impl GeneratorHelp for StandardGeneratorHelper {
    fn pre_fetch(&mut self, backend: &mut PcodeBackend) -> Box<[ContextOption]> {
        let mut ret = Vec::new();
        let cpsr = backend.read_register::<u32>(ArmRegister::Cpsr).unwrap();
        let new_mode = ArmCpuMode::from_cpsr(cpsr);

        // only write context variable if thumb mode changed
        if let Some(previous_mode) = self.previous_mode {
            if previous_mode == new_mode {
                return Vec::new().into_boxed_slice();
            }
        }

        // previous is none or is different than thumb mode now
        debug!("Arm processor instruction set changed to {new_mode:?}");
        // set thumb mode in translator
        ret.push(ContextOption::ThumbMode(new_mode.is_thumb()));

        self.previous_mode = Some(new_mode);

        ret.into_boxed_slice()
    }
}

/// Thumb mode enabling for the Armv7-M processors.
///
/// Sets the thumb mode context variable on first execution.
#[derive(Debug, Default)]
pub struct ThumbOnlyGeneratorHelper {
    /// `false` on creation, changed to true after setting the thumb mode context on first call.
    thumb_already_set: bool,
}

impl GeneratorHelp for ThumbOnlyGeneratorHelper {
    fn pre_fetch(&mut self, _backend: &mut PcodeBackend) -> Box<[ContextOption]> {
        if !self.thumb_already_set {
            self.thumb_already_set = true;
            vec![ContextOption::ThumbMode(true)]
        } else {
            Vec::new()
        }
        .into_boxed_slice()
    }
}
