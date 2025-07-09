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
use styx_core::prelude::*;

use tracing::{trace, warn};

use super::{AssignmentBank, CoreEventController, Event, RoutingBank};

/// Catches RAISE calls from the cpu backend and sends it to the event controller.
pub fn interrupt_hook(proc: CoreHandle, intno: ExceptionNumber) -> Result<(), UnknownError> {
    warn!(
        "caught interrupt: {intno}, pc: 0x{:x}",
        proc.cpu.pc().unwrap()
    );

    let event = Event::from_event_irqn_expect(intno).unwrap();

    if event.is_raise_latchable() {
        proc.event_controller.latch(intno).unwrap();
    } else {
        warn!("non raise latchable interrupt caught {intno}")
    }
    Ok(())
}

pub fn reti_hook(proc: CoreHandle) -> Result<(), UnknownError> {
    let cec = proc.event_controller.get_impl::<CoreEventController>()?;

    cec.return_from_interrupt(proc.cpu);
    Ok(())
}

/// Handles writes to interrupt mask and interrupt latch registers. Interrupt pending register
/// cannot be written to so it is not hooked.
pub fn core_interrupt_registers_hook(
    proc: CoreHandle,
    address: u64,
    size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let cec = proc.event_controller.get_impl::<CoreEventController>()?;

    debug_assert_eq!(size, 4);

    // bottom bytes are for modifying interrupts
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&data[0..2]);
    let data_u16 = u16::from_le_bytes(buf);
    trace!("0x{data_u16:X} written to 0x{address:X}");

    match address as u32 {
        super::sys::IMASK => cec.exceptions.set_masks(data_u16),
        super::sys::ILAT => cec.exceptions.clear_latches(data_u16),

        _ => warn!("unsupported address write to core interrupt registers: 0x{address:X}"),
    }
    Ok(())
}

pub fn system_interrupt_registers_hook(
    proc: CoreHandle,
    address: u64,
    size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let cec = proc.event_controller.get_impl::<CoreEventController>()?;
    debug_assert_eq!(size, 4);

    let mut buf = [0u8; 4];
    buf.copy_from_slice(data);
    let data_u32 = u32::from_le_bytes(buf);
    trace!("0x{data_u32:X} written to 0x{address:X}");

    let mut system = cec.system.lock().unwrap();
    match address as u32 {
        super::sys::SIC_IMASK0 => system.set_masks(RoutingBank::Zero, data_u32),
        super::sys::SIC_IMASK1 => system.set_masks(RoutingBank::One, data_u32),
        super::sys::SIC_IWR0 => system.set_wakeup(RoutingBank::Zero, data_u32),
        super::sys::SIC_IWR1 => system.set_wakeup(RoutingBank::One, data_u32),
        super::sys::SIC_IAR0 => system.set_assignment(AssignmentBank::Zero, data_u32),
        super::sys::SIC_IAR1 => system.set_assignment(AssignmentBank::One, data_u32),
        super::sys::SIC_IAR2 => system.set_assignment(AssignmentBank::Two, data_u32),
        super::sys::SIC_IAR3 => system.set_assignment(AssignmentBank::Three, data_u32),
        super::sys::SIC_IAR4 => system.set_assignment(AssignmentBank::Four, data_u32),
        super::sys::SIC_IAR5 => system.set_assignment(AssignmentBank::Five, data_u32),
        super::sys::SIC_IAR6 => system.set_assignment(AssignmentBank::Six, data_u32),
        super::sys::SIC_IAR7 => system.set_assignment(AssignmentBank::Seven, data_u32),

        _ => warn!("unsupported address write to system interrupt registers: 0x{address:X}"),
    }
    Ok(())
}
