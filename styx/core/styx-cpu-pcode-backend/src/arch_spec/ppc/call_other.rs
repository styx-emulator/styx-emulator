// SPDX-License-Identifier: BSD-2-Clause
use log::debug;
use styx_pcode::pcode;
use styx_processor::{cpu::CpuBackend, event_controller::EventController, memory::Mmu};

use crate::{
    call_other::{CallOtherCallback, CallOtherHandleError},
    PCodeStateChange, PcodeBackend,
};

const SVC_IRQN: i32 = 8;
const RFI_WORKAROUND_ADDRESS: u64 = 0x99999998;

#[derive(Debug)]
pub struct SystemCall;
impl CallOtherCallback for SystemCall {
    fn handle(
        &mut self,
        _backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[pcode::VarnodeData],
        _output: Option<&pcode::VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let delayed_interrupt = PCodeStateChange::DelayedInterrupt(SVC_IRQN);
        Ok(delayed_interrupt)
    }
}

///
/// Code from ppc32_embedded.slaspec
/// ```slaspec
/// #rfi    0x4c 00 00 64
/// :rfi        is $(NOTVLE) & OP=19 & BITS_11_25=0 & XOP_1_10=50 & BIT_0=0
/// {
///     MSR = returnFromInterrupt(MSR, SRR1);
///     local ra = SRR0;
///     return[ra];
/// }
/// ```
#[derive(Debug)]
pub struct ReturnFromInterrupt;
impl CallOtherCallback for ReturnFromInterrupt {
    fn handle(
        &mut self,
        cpu: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[pcode::VarnodeData],
        output: Option<&pcode::VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let pc = cpu.pc().unwrap();
        let [_msr, srr1_varnode] = inputs else {
            return Err(CallOtherHandleError::Other("invalid inputs".into()));
        };
        let Some(new_msr_varnode) = output else {
            return Err(CallOtherHandleError::Other("invalid output".into()));
        };

        let srr1 = cpu.space_manager.read(srr1_varnode).unwrap();
        debug!("return from interrupt @ 0x{pc:X}");
        cpu.space_manager.write(new_msr_varnode, srr1).unwrap();
        // pcode change pc for us
        // temporary workaround for post interrupt actions
        // this will cause an invalid instruction hook to get called, which gets us a
        // reference to the CEC, which allows for us to do post-interrupt things on
        // the event controller.
        Ok(PCodeStateChange::InstructionAbsolute(
            RFI_WORKAROUND_ADDRESS,
        ))
    }
}
