// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
use super::helpers::StackPointerManager;
use crate::{
    call_other::{CallOtherCallback, CallOtherHandleError},
    memory::sized_value::SizedValue,
    PCodeStateChange, PcodeBackend,
};
use log::{trace, warn};
use styx_cpu_type::arch::arm::{arm_coproc_registers, ArmRegister, CoProcessorValue};
use styx_pcode::pcode::VarnodeData;
use styx_processor::{
    cpu::{CpuBackend, CpuBackendExt},
    event_controller::EventController,
    memory::Mmu,
};
use styx_sync::sync::Arc;

/// Interrupt number for SVCall.
const SVC_IRQN: i32 = -5;

#[derive(Debug, Default)]
pub struct SoftwareInterruptCallOther;
impl CallOtherCallback for SoftwareInterruptCallOther {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let input_value = backend.read(&inputs[0]).unwrap();

        let interrupt_number = input_value.to_u128().unwrap();
        let interrupt_number: i32 = interrupt_number.try_into().unwrap();
        trace!("Interrupt no: {interrupt_number}");
        assert_eq!(interrupt_number, 0);

        Ok(PCodeStateChange::DelayedInterrupt(SVC_IRQN))
    }
}

#[derive(Debug)]
pub struct EnableIRQInterrupts;
impl CallOtherCallback for EnableIRQInterrupts {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        warn!("EnableIRQInterrupts called");

        let primask_value = inputs
            .first()
            .map(|i| backend.read(i).unwrap().to_u128().unwrap())
            .unwrap_or(0);
        backend
            .write_register(ArmRegister::Primask, primask_value as u32)
            .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct DisableIRQInterrupts;
impl CallOtherCallback for DisableIRQInterrupts {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        warn!("DisableIRQInterrupts called");

        backend.write_register(ArmRegister::Primask, 1u32).unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct EnableFIQInterrupts;
impl CallOtherCallback for EnableFIQInterrupts {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        warn!("EnableFIQInterrupts called");

        let faultmask_value = inputs
            .first()
            .map(|i| backend.read(i).unwrap().to_u128().unwrap())
            .unwrap_or(0);
        backend
            .write_register(ArmRegister::Faultmask, faultmask_value as u32)
            .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct DisableFIQInterrupts;
impl CallOtherCallback for DisableFIQInterrupts {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        warn!("DisableFIQInterrupts called");

        backend
            .write_register(ArmRegister::Faultmask, 1u32)
            .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

/// The BASEPRI register is a mask register and masks all interrupt priorities levels which are
/// ‘numerically equal or higher (lower urgency!) than the BASEPRI value’.
#[derive(Debug)]
pub struct SetBasePriority;
impl CallOtherCallback for SetBasePriority {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let new_base_priority = backend.read(&inputs[0]).unwrap();
        warn!(
            "Base priority tried to be set to {new_base_priority} at 0x{:X}",
            backend.pc().unwrap()
        );
        backend
            .write_register(
                ArmRegister::Basepri,
                new_base_priority.to_u128().unwrap() as u32,
            )
            .unwrap();
        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct IsPrivileged;
impl CallOtherCallback for IsPrivileged {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        backend
            .write(output.unwrap(), SizedValue::from_u128(1, 1))
            .unwrap();
        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct SetMainStackPointer;
impl CallOtherCallback for SetMainStackPointer {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let input = inputs
            .first()
            .expect("no new main stack pointer given to call other invocation");
        let new_msp = backend.read(input).unwrap().to_u128().unwrap() as u32;
        trace!(
            "Setting Master Stack Pointer to 0x{new_msp:X} at pc=0x{:X}",
            backend.pc().unwrap()
        );
        backend.write_register(ArmRegister::Msp, new_msp).unwrap();
        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct SetProcessStackPointer {
    #[allow(dead_code)] // TODO: remove
    pub stack_pointer_manager: Arc<StackPointerManager>,
}
impl CallOtherCallback for SetProcessStackPointer {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug_assert_eq!(inputs.len(), 1);
        debug_assert!(_output.is_none());
        let new_psp = backend.read(&inputs[0]).unwrap().to_u128().unwrap() as u32;
        trace!(
            "Setting Process Stack Pointer to 0x{new_psp:X} at pc=0x{:X}",
            backend.pc().unwrap()
        );

        backend.write_register(ArmRegister::Psp, new_psp).unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct GetMainStackPointer;
impl CallOtherCallback for GetMainStackPointer {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug_assert_eq!(inputs.len(), 0);
        debug_assert!(output.is_some());

        let output = output.unwrap();
        let value = SizedValue::from_u128(
            backend.read_register::<u32>(ArmRegister::Msp).unwrap() as u128,
            output.size as u8,
        );
        backend.write(output, value).unwrap();
        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct GetProcessStackPointer {
    #[allow(dead_code)] // TODO: remove
    pub stack_pointer_manager: Arc<StackPointerManager>,
}
impl CallOtherCallback for GetProcessStackPointer {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug_assert_eq!(inputs.len(), 0);
        debug_assert!(output.is_some());

        let output = output.unwrap();
        let value = SizedValue::from_u128(
            backend.read_register::<u32>(ArmRegister::Psp).unwrap() as u128,
            output.size as u8,
        );
        backend.write(output, value).unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[inline]
/// `define register offset=0x0200 size=4 [ cr0 cr1 cr2 cr3 cr4 cr5 cr6 cr7 cr8 cr9 cr10 cr11 cr12 cr13 cr14 cr15 ];`
///
/// returns the coprocessor register number that is at some offset
const fn map_varnode_offset_to_coproc_num(offset: u64) -> u8 {
    debug_assert!(offset >= 0x200);

    ((offset - 0x200) / 4) as u8
}

#[derive(Debug)]
pub struct CoprocMovefromControl;

impl CallOtherCallback for CoprocMovefromControl {
    fn handle(
        &mut self,
        cpu: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug_assert_eq!(inputs.len(), 0);
        debug_assert!(output.is_some());

        let output = output.unwrap();

        let value = SizedValue::from_u128(
            cpu.read_register::<CoProcessorValue>(arm_coproc_registers::SCTLR)
                .unwrap()
                .value as u128,
            output.size as u8,
        );

        cpu.write(output, value).unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct CoprocMovetoControl;

impl CallOtherCallback for CoprocMovetoControl {
    fn handle(
        &mut self,
        cpu: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug_assert_eq!(inputs.len(), 1);
        debug_assert!(output.is_none());

        let new_sctlr = cpu.read(&inputs[0]).unwrap().to_u128().unwrap();

        cpu.write_register(
            arm_coproc_registers::SCTLR,
            arm_coproc_registers::SCTLR.with_value(new_sctlr as u64),
        )
        .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct CoprocMovefromPeripheralSystem;

/// equivalent to: `mrc p15, <opc1>, <Rt>, c15, <Crm>, <opc2>`
///
/// `Rd = coproc_movefrom_Peripheral_System(t_opc2,t_crm,t_op1);`
///
/// see <https://developer.arm.com/documentation/100511/0401/system-control/register-summary/cp15-system-control-registers-grouped-by-crn-order>
impl CallOtherCallback for CoprocMovefromPeripheralSystem {
    fn handle(
        &mut self,
        cpu: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug_assert_eq!(inputs.len(), 3);
        debug_assert!(output.is_some());

        let output = output.unwrap();

        let opc2 = cpu.read(&inputs[0]).unwrap().to_u128().unwrap() as u8;
        let crm = map_varnode_offset_to_coproc_num(inputs[1].offset);
        let opc1 = cpu.read(&inputs[2]).unwrap().to_u128().unwrap() as u8;

        if opc1 == 4 && crm == 0 && opc2 == 0 {
            let value = SizedValue::from_u128(
                cpu.read_register::<CoProcessorValue>(arm_coproc_registers::CBAR)
                    .unwrap()
                    .value as u128,
                output.size as u8,
            );
            cpu.write(output, value).unwrap();
        } else {
            warn!("unhandled case in CoprocMovefromPeripheralSystem");
        }

        Ok(PCodeStateChange::Fallthrough)
    }
}

/// coprocessor_movefromRt(t_cpn,t_op1,t_opc2,CRn,CRm);
#[derive(Debug)]
pub struct CoprocessorMovefromRt;
impl CallOtherCallback for CoprocessorMovefromRt {
    fn handle(
        &mut self,
        cpu: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug_assert_eq!(inputs.len(), 5);
        debug_assert!(output.is_some());

        let output = output.unwrap();

        let cpn = cpu.read(&inputs[0]).unwrap().to_u128().unwrap() as u8;
        let opc1 = cpu.read(&inputs[1]).unwrap().to_u128().unwrap() as u8;
        let opc2 = cpu.read(&inputs[2]).unwrap().to_u128().unwrap() as u8;
        let crn = map_varnode_offset_to_coproc_num(inputs[3].offset);
        let crm = map_varnode_offset_to_coproc_num(inputs[4].offset);

        if cpn == 15 && opc1 == 0 && opc2 == 0 && crn == 12 && crm == 0 {
            let value = SizedValue::from_u128(
                cpu.read_register::<CoProcessorValue>(arm_coproc_registers::VBAR)
                    .unwrap()
                    .value as u128,
                output.size as u8,
            );
            cpu.write(output, value).unwrap();
        } else {
            warn!(
                "unhandled case in CoprocessorMovefromRt: cpn={cpn}, opc1={opc1}, opc2={opc2}, crn={crn}, crm={crm}"
            );
        }

        Ok(PCodeStateChange::Fallthrough)
    }
}
