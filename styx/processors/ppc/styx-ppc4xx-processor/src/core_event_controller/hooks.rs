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

use styx_core::cpu::arch::ppc32::Ppc32Register;
use styx_core::hooks::{CodeHook, Resolution};
use styx_core::prelude::log::debug;
use styx_core::prelude::*;
use tracing::trace;

use super::CoreEventController;

/// Whenever we return from an interrupt we jump to this address so that
/// the event controller can handle post-interrupt events.
const RFI_MAGIC_NUMBER: u64 = 0x99999998;

/// Catches system calls from the cpu backend and sends it to the event controller.
pub fn interrupt_hook(proc: CoreHandle, intno: ExceptionNumber) -> Result<(), UnknownError> {
    debug!(
        "caught interrupt: {intno}, pc: 0x{:x}",
        proc.cpu.pc().unwrap()
    );

    proc.event_controller.execute(intno, proc.cpu, proc.mmu)?;
    Ok(())
}

/// Used to catch our return from interrupt events
pub fn interrupt_return_hook(proc: CoreHandle) -> Result<Resolution, UnknownError> {
    if proc.cpu.pc().unwrap() != RFI_MAGIC_NUMBER {
        trace!("incorrect pc, not fixing");
        return Ok(Resolution::NotFixed);
    }

    let srr0 = proc.cpu.read_register::<u32>(Ppc32Register::SRR0).unwrap();
    trace!("correct pc, fixing by jumping to srr0 (0x{srr0:?})");

    // TODODODODODODOD
    // proc.event_controller.post_irq_route_hook();
    proc.cpu.set_pc(srr0.into()).unwrap();

    Ok(Resolution::Fixed)
}

/// Called on every instruction
pub struct EventsContainerCodeHook;
impl CodeHook for EventsContainerCodeHook {
    fn call(&mut self, proc: CoreHandle) -> Result<(), UnknownError> {
        let cec = proc.event_controller.get_impl::<CoreEventController>()?;
        cec.exceptions.code_hook(proc.cpu);
        Ok(())
    }
}
