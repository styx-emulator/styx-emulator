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
