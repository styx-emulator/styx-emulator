// SPDX-License-Identifier: BSD-2-Clause

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
