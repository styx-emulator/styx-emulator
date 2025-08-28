// SPDX-License-Identifier: BSD-2-Clause
use super::helpers::StackPointerManager;
use crate::register_manager::RegisterCallbackCpu;
use crate::{
    memory::{sized_value::SizedValue, space_manager::SpaceManager},
    register_manager::{RegisterCallback, RegisterHandleError},
};
use log::{trace, warn};
use styx_cpu_type::arch::{arm::ArmRegister, backends::ArchRegister};
use styx_pcode::pcode::{SpaceName, VarnodeData};
use styx_processor::cpu::{CpuBackend, CpuBackendExt};
use styx_sync::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

// APSR constants
/// APSR bit offset for the condition flags.
const APSR_BIT_OFFSET_COND_FLAGS: u32 = 27;
/// APSR bit offset for the greater-than-equal (GE) flags.
const APSR_BIT_OFFSET_GE_FLAGS: u32 = 16;
/// APSR mask - bits 0-15 and 20-26 are reserved/SBZ.
const APSR_MASK: u32 = 0xF80F_0000;

/// APSR register for Armv7-A, Armv7-R, and Armv7-M architectures.
#[derive(Debug, Default)]
pub struct ApsrHandler;
impl<T: CpuBackend> RegisterCallback<T> for ApsrHandler {
    fn read(
        &mut self,
        register: ArchRegister,
        cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<SizedValue, RegisterHandleError> {
        if register != ArmRegister::Apsr.into() {
            return Err(RegisterHandleError::CannotHandleRegister(register));
        }

        // Start with the condition flags in the top five bits.
        let mut apsr = armv7_get_condition_flags(cpu.space_manager(), APSR_BIT_OFFSET_COND_FLAGS);
        // Puts the GE flag bits in bits [19:16] as described in the ARMv7-A/R and ARMv7-M
        // documentation.
        apsr |= arm7_get_ge_flags(cpu.space_manager(), APSR_BIT_OFFSET_GE_FLAGS);

        // technically for the M series we could read from XPSR and mask the APSR bits but to
        // make this handler agnostic to A/M/R processors we can just calculate from the
        // internal flags.

        Ok(SizedValue::from_u64(apsr as u64, 4))
    }

    /// TODO does not implement RAZ/SBZP bits for A series.
    /// RAZ/SBZP should be read as zero and ignored on writes.
    fn write(
        &mut self,
        _register: ArchRegister,
        value: SizedValue,
        _cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<(), RegisterHandleError> {
        warn!("WRITE APSR");
        let raw_value = value.to_u64().unwrap() as u32;

        let _masked_apsr = raw_value & APSR_MASK;

        // TODO write condition flags out!
        Ok(())
    }
}

#[derive(Debug)]
pub struct ControlHandler {
    stack_pointer_manager: Arc<StackPointerManager>,
}

impl ControlHandler {
    pub fn new(stack_pointer_manager: Arc<StackPointerManager>) -> Self {
        Self {
            stack_pointer_manager,
        }
    }
}

impl<T: CpuBackend> RegisterCallback<T> for ControlHandler {
    fn read(
        &mut self,
        _register: ArchRegister,
        _cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<SizedValue, RegisterHandleError> {
        let mut out = 0u32;
        out |= (self.stack_pointer_manager.get_stack_pointer_select() as u32) << 1;

        Ok(SizedValue::from_u64(out as u64, 4))
    }

    fn write(
        &mut self,
        _register: ArchRegister,
        value: SizedValue,
        cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<(), RegisterHandleError> {
        let value = value.to_u64().unwrap() as u32;

        let spsel = ((value >> 1) & 1) == 1;
        self.stack_pointer_manager
            .set_stack_pointer_select(spsel, cpu);

        trace!(
            "New spsel: {}",
            self.stack_pointer_manager.get_stack_pointer_select()
        );

        Ok(())
    }
}

#[derive(Debug)]
pub struct MainStackPointerHandler {
    pub stack_pointer_manager: Arc<StackPointerManager>,
}
impl<T: CpuBackend> RegisterCallback<T> for MainStackPointerHandler {
    fn read(
        &mut self,
        register: ArchRegister,
        cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<SizedValue, RegisterHandleError> {
        if register != ArmRegister::Msp.into() {
            return Err(RegisterHandleError::CannotHandleRegister(register));
        }

        let msp = self.stack_pointer_manager.get_main(cpu) as u64;

        trace!("MSP: 0x{msp:X}");
        Ok(SizedValue::from_u64(msp, 4))
    }

    fn write(
        &mut self,
        _register: ArchRegister,
        value: SizedValue,
        cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<(), RegisterHandleError> {
        trace!("new MSP: 0x{:X}", value.to_u64().unwrap());

        let new_msp = value.to_u64().unwrap() as u32;
        self.stack_pointer_manager.set_main(new_msp, cpu);

        Ok(())
    }
}

#[derive(Debug)]
pub struct ProcessStackPointerHandler {
    pub stack_pointer_manager: Arc<StackPointerManager>,
}

impl<T: CpuBackend> RegisterCallback<T> for ProcessStackPointerHandler {
    fn read(
        &mut self,
        register: ArchRegister,
        cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<SizedValue, RegisterHandleError> {
        if register != ArmRegister::Psp.into() {
            return Err(RegisterHandleError::CannotHandleRegister(register));
        }
        let psp = self.stack_pointer_manager.get_process(cpu) as u64;
        trace!("PSP: 0x{psp:X}");
        Ok(SizedValue::from_u64(psp, 4))
    }

    fn write(
        &mut self,
        _register: ArchRegister,
        value: SizedValue,
        cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<(), RegisterHandleError> {
        trace!("NEW PSP: 0x{:X}", value.to_u64().unwrap() as u32);

        self.stack_pointer_manager
            .set_process(value.to_u64().unwrap() as u32, cpu);

        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct BasePriorityHandler {
    base_priority: AtomicU64,
}
impl<T: CpuBackend> RegisterCallback<T> for BasePriorityHandler {
    fn read(
        &mut self,
        register: ArchRegister,
        _cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<SizedValue, RegisterHandleError> {
        if register != ArmRegister::Basepri.into() {
            return Err(RegisterHandleError::CannotHandleRegister(register));
        }
        Ok(SizedValue::from_u64(
            self.base_priority.load(Ordering::Acquire),
            4,
        ))
    }

    fn write(
        &mut self,
        register: ArchRegister,
        value: SizedValue,
        _cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<(), RegisterHandleError> {
        if register != ArmRegister::Basepri.into() {
            return Err(RegisterHandleError::CannotHandleRegister(register));
        }

        // bits 8-31 are reserved
        self.base_priority
            .store(value.to_u64().unwrap() & 0xFF, Ordering::Release);

        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct PriorityMaskRegister {
    priority_mask: AtomicU64,
}
impl<T: CpuBackend> RegisterCallback<T> for PriorityMaskRegister {
    fn read(
        &mut self,
        register: ArchRegister,
        _cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<SizedValue, RegisterHandleError> {
        if register != ArmRegister::Primask.into() {
            return Err(RegisterHandleError::CannotHandleRegister(register));
        }
        let priority_mask = self.priority_mask.load(Ordering::Acquire);
        trace!("Read prim mask: {priority_mask}");
        Ok(SizedValue::from_u64(priority_mask, 4))
    }

    fn write(
        &mut self,
        register: ArchRegister,
        value: SizedValue,
        cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<(), RegisterHandleError> {
        if register != ArmRegister::Primask.into() {
            return Err(RegisterHandleError::CannotHandleRegister(register));
        }

        let new_priority_mask = value.to_u64().unwrap() & 0x1;
        trace!(
            "new prim mask: {} at 0x{:X}",
            new_priority_mask,
            cpu.pc().unwrap()
        );
        // bits 1-31 are reserved
        self.priority_mask
            .store(new_priority_mask, Ordering::Release);

        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct FaultMaskRegister {
    fault_mask: AtomicU64,
}
impl<T: CpuBackend> RegisterCallback<T> for FaultMaskRegister {
    fn read(
        &mut self,
        register: ArchRegister,
        _cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<SizedValue, RegisterHandleError> {
        if register != ArmRegister::Faultmask.into() {
            return Err(RegisterHandleError::CannotHandleRegister(register));
        }
        Ok(SizedValue::from_u64(
            self.fault_mask.load(Ordering::Acquire),
            4,
        ))
    }

    fn write(
        &mut self,
        register: ArchRegister,
        value: SizedValue,
        _cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<(), RegisterHandleError> {
        if register != ArmRegister::Faultmask.into() {
            return Err(RegisterHandleError::CannotHandleRegister(register));
        }

        // bits 1-31 are reserved
        self.fault_mask
            .store(value.to_u64().unwrap() & 0x1, Ordering::Release);

        Ok(())
    }
}

/// IPSR handler for Armv7-M
///
/// Supports reads and writes to the bottom 9 bits as documented.
#[derive(Debug, Default)]
pub struct Ipsr {
    ipsr: AtomicU64,
}
impl<T: CpuBackend> RegisterCallback<T> for Ipsr {
    fn read(
        &mut self,
        register: ArchRegister,
        _cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<SizedValue, RegisterHandleError> {
        if register != ArmRegister::Ipsr.into() {
            return Err(RegisterHandleError::CannotHandleRegister(register));
        }

        Ok(SizedValue::from_u64(self.ipsr.load(Ordering::Acquire), 4))
    }

    fn write(
        &mut self,
        register: ArchRegister,
        value: SizedValue,
        _cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<(), RegisterHandleError> {
        if register != ArmRegister::Ipsr.into() {
            return Err(RegisterHandleError::CannotHandleRegister(register));
        }

        // bits 0-9 are for ipsr, others are reserved
        self.ipsr
            .store(value.to_u64().unwrap() & 0x1FF, Ordering::Release);

        Ok(())
    }
}

/// EPSR handler for Armv7-M (thumb mode always enabled)
///
/// # Note
///
/// Does not support IT/ICI saving. This relates to saving execution context in the middle of an IT
/// block or multi-register load/store operation.
#[derive(Debug, Default)]
pub struct Epsr;
impl<T: CpuBackend> RegisterCallback<T> for Epsr {
    fn read(
        &mut self,
        register: ArchRegister,
        _cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<SizedValue, RegisterHandleError> {
        if register != ArmRegister::Epsr.into() {
            return Err(RegisterHandleError::CannotHandleRegister(register));
        }

        // Bit 24 indicates thumb mode
        // For -M profile this is always set
        let epsr = 1 << 24;

        Ok(SizedValue::from_u64(epsr, 4))
    }

    fn write(
        &mut self,
        _register: ArchRegister,
        value: SizedValue,
        cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<(), RegisterHandleError> {
        let epsr = value.to_u64().unwrap();
        warn!(
            "Unexpected write to EPSR: 0x{:X} at pc=0x{:X}",
            epsr,
            cpu.pc().unwrap()
        );

        Ok(())
    }
}

const CPSR_BIT_OFFSET_THUMB_BIT: u32 = 5;
const CPSR_MASK_THUMB_BIT: u32 = 1 << CPSR_BIT_OFFSET_THUMB_BIT;

/// Current Program Status Register (CPSR)
#[derive(Debug, Default)]
pub struct CpsrHandler;
impl<T: CpuBackend> RegisterCallback<T> for CpsrHandler {
    fn read(
        &mut self,
        register: ArchRegister,
        cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<SizedValue, RegisterHandleError> {
        if register != ArmRegister::Cpsr.into() {
            return Err(RegisterHandleError::CannotHandleRegister(register));
        }

        // Get current cpsr value.
        let mut cpsr = arm7a_get_cpsr(cpu);

        // Clear APSR bits and thumb execution state bit.
        cpsr &= !APSR_MASK | !CPSR_MASK_THUMB_BIT;

        // Get the current APSR (condition and greater-than-equal flags).
        cpsr |= cpu.read_register::<u32>(ArmRegister::Apsr).unwrap();

        // NOTE: We are missing:
        // - E-bit [9]
        // - Mask bits [8:6]
        // - Mode bits [4:0]

        cpsr = add_flag(
            cpsr,
            CPSR_BIT_OFFSET_THUMB_BIT,
            THUMB_BIT_OFFSET,
            cpu.space_manager(),
        );

        trace!("Read from cpsr: 0x{cpsr:X}");
        Ok(SizedValue::from_u64(cpsr as u64, 4))
    }

    fn write(
        &mut self,
        register: ArchRegister,
        value: SizedValue,
        cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<(), RegisterHandleError> {
        if register != ArmRegister::Cpsr.into() {
            return Err(RegisterHandleError::CannotHandleRegister(register));
        }

        // FIXME: We need to make sure all of this is writable.
        arm7a_set_cpsr(cpu, value);
        Ok(())
    }
}

/// XPSR register handler for Armv7-M processors.
///
/// Reads are computed by reading from the APSR, IPSR, and EPSR and overlapping. Writes are
/// propagated to the same three registers. APSR, IPSR, and EPSR must have reserved bits read as 0.
///
/// # Documentation
///
/// From the Armv7-M Manual:
///
/// The EPSR The EPSR contains the T bit, that is set to 1 to indicate that the processor executes
/// Thumb instructions, and an overlaid ICI or IT field that supports interrupt-continue load/store
/// instructions and the IT instruction.
///
/// Note: The Arm A and R architecture profiles have two alternative instruction sets, Arm and
/// Thumb. The instruction set state identifies the current instruction set, and the PSR T bit
/// identifies that state. The M profile supports only the Thumb instruction set, and therefore the
/// processor can execute instructions only if the T bit is set to 1.
///
/// All fields read as zero using an MRS instruction, and the processor ignores writes to the EPSR
/// by an MSR instruction.
///
/// The EPSR.T bit supports the Arm architecture interworking model, however, as Armv7-M only
/// supports execution of Thumb instructions, it must always be maintained with the value 1. Updates
/// to the PC that comply with the Thumb instruction interworking rules must update the EPSR.T
/// accordingly. Instruction execution with EPSR.T set to 0 causes the invalid state UsageFault,
/// INVSTATE. A reset:
///
/// - Sets the T bit to the value of `bit[0]` of the reset vector. This bit must be 1 if the
///   processor is to execute the code indicated by the reset vector. If this bit is 0, the processor
///   takes a HardFault exception and enters the HardFault handler, with the stacked ReturnAddress()
///   value pointing to the reset handler, and the T bit of the stacked xPSR value set to 0.
///
/// - Clears the IT/ICI bits t
///
#[derive(Debug, Default)]
pub struct XpsrHandler;
impl<T: CpuBackend> RegisterCallback<T> for XpsrHandler {
    fn read(
        &mut self,
        register: ArchRegister,
        cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<SizedValue, RegisterHandleError> {
        if register != ArmRegister::Xpsr.into() {
            return Err(RegisterHandleError::CannotHandleRegister(register));
        }

        let apsr = cpu.read_register::<u32>(ArmRegister::Apsr).unwrap();
        let ipsr = cpu.read_register::<u32>(ArmRegister::Ipsr).unwrap();
        let epsr = cpu.read_register::<u32>(ArmRegister::Epsr).unwrap();

        let xpsr = apsr | ipsr | epsr;

        Ok(SizedValue::from_u64(xpsr as u64, 4))
    }

    fn write(
        &mut self,
        register: ArchRegister,
        value: SizedValue,
        cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<(), RegisterHandleError> {
        if register != ArmRegister::Xpsr.into() {
            return Err(RegisterHandleError::CannotHandleRegister(register));
        }

        let xpsr = value.to_u64().unwrap() as u32;

        cpu.write_register(ArmRegister::Apsr, xpsr).unwrap();
        cpu.write_register(ArmRegister::Ipsr, xpsr).unwrap();
        cpu.write_register(ArmRegister::Epsr, xpsr).unwrap();

        Ok(())
    }
}

// These varnode offsets are from the slaspec.
/// Varnode name "NG"
const NEGATIVE_FLAG_OFFSET: u64 = 0x60;
/// Varnode name "ZR"
const ZERO_FLAG_OFFSET: u64 = 0x62;
/// Varnode name "CY"
const CARRY_FLAG_OFFSET: u64 = 0x63;
/// Varnode name "OV"
const OVERFLOW_FLAG_OFFSET: u64 = 0x64;
/// Varnode name "Q"
const SATURATION_FLAG_OFFSET: u64 = 0x6A;
/// Varnode name "GE1"
const GREATER_THAN_OR_EQUAL1_OFFSET: u64 = 0x6B;
/// Varnode name "GE2"
const GREATER_THAN_OR_EQUAL2_OFFSET: u64 = 0x6C;
/// Varnode name "GE3"
const GREATER_THAN_OR_EQUAL3_OFFSET: u64 = 0x6D;
/// Varnode name "GE4"
const GREATER_THAN_OR_EQUAL4_OFFSET: u64 = 0x6E;
/// Varnode name "cpsr"
const CPSR_OFFSET: u64 = 0x70;
/// Varnode name "TB"
const THUMB_BIT_OFFSET: u64 = 0x69;

/// Puts the condition flags (N, Z, C, V and Q) at the specified offset.
fn armv7_get_condition_flags(backend: &mut SpaceManager, bit_offset: u32) -> u32 {
    let mut flags = 0u32;
    let mut offset = bit_offset;
    flags = add_flag(flags, offset, OVERFLOW_FLAG_OFFSET, backend);
    offset += 1;
    flags = add_flag(flags, offset, CARRY_FLAG_OFFSET, backend);
    offset += 1;
    flags = add_flag(flags, offset, ZERO_FLAG_OFFSET, backend);
    offset += 1;
    flags = add_flag(flags, offset, NEGATIVE_FLAG_OFFSET, backend);
    offset += 1;
    flags = add_flag(flags, offset, SATURATION_FLAG_OFFSET, backend);

    flags
}

/// Puts the GE flag bits at the specified offset.
fn arm7_get_ge_flags(backend: &mut SpaceManager, bit_offset: u32) -> u32 {
    let mut ge = 0u32;
    let mut offset = bit_offset;
    ge = add_flag(ge, offset, GREATER_THAN_OR_EQUAL1_OFFSET, backend);
    offset += 1;
    ge = add_flag(ge, offset, GREATER_THAN_OR_EQUAL2_OFFSET, backend);
    offset += 1;
    ge = add_flag(ge, offset, GREATER_THAN_OR_EQUAL3_OFFSET, backend);
    offset += 1;
    ge = add_flag(ge, offset, GREATER_THAN_OR_EQUAL4_OFFSET, backend);
    ge
}

fn add_flag(flag: u32, bit_offset: u32, flag_offset: u64, spaces: &mut SpaceManager) -> u32 {
    let varnode = VarnodeData {
        space: SpaceName::Register,
        offset: flag_offset,
        size: 1,
    };
    let value = spaces.read(&varnode).unwrap().to_u64().unwrap() as u32 & 1;
    flag | (value << bit_offset)
}

fn arm7a_get_cpsr<C: CpuBackend>(backend: &mut dyn RegisterCallbackCpu<C>) -> u32 {
    let varnode = VarnodeData {
        space: SpaceName::Register,
        offset: CPSR_OFFSET,
        size: 4,
    };
    backend.read(&varnode).unwrap().to_u64().unwrap() as u32
}

fn arm7a_set_cpsr<C: CpuBackend>(backend: &mut dyn RegisterCallbackCpu<C>, value: SizedValue) {
    let varnode = VarnodeData {
        space: SpaceName::Register,
        offset: CPSR_OFFSET,
        size: 4,
    };
    backend.write(&varnode, value).unwrap();
}

#[derive(Debug, Default)]
pub struct FloatingPointExtensionHandler {
    value: AtomicU64,
}
impl<T: CpuBackend> RegisterCallback<T> for FloatingPointExtensionHandler {
    fn read(
        &mut self,
        _register: ArchRegister,
        _cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<SizedValue, RegisterHandleError> {
        Ok(SizedValue::from_u64(self.value.load(Ordering::Acquire), 4))
    }

    fn write(
        &mut self,
        _register: ArchRegister,
        value: SizedValue,
        _cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<(), RegisterHandleError> {
        self.value.store(value.to_u64().unwrap(), Ordering::Release);

        Ok(())
    }
}
