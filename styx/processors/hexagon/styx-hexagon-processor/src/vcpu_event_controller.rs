// SPDX-License-Identifier: BSD-2-Clause

//! Hexagon vcpu interrupt controller.
//! While the hexagon l2vic steers interrupts to individual vCPUs,
//! we need an interrupt controller for each VCPU. Things look like this:
//!
//!                                      -------------------------
//!                         |----------> | vCPU event controller |  ---> vCPU0
//!                         |            -------------------------
//!                         |
//!    ---------            |
//!    | l2vic |------------
//!    ---------            |
//!                         |
//!                         |            -------------------------
//!                         |----------> | vCPU event controller | ---> vCPU1
//!                                     -------------------------
//!
//! As such, the l2vic implements `PrimaryEventControllerImpl` and
//! This file implements `EventControllerImpl`.

use std::{collections::VecDeque, sync::Arc};

use styx_core::{
    arch::hexagon::{
        register_fields::{Ipendad, Ssr},
        GlobalHexagonRegister, HexagonRegister,
    },
    cpu::{
        CpuBackend, CpuBackendExt, HexagonInterruptCause, HexagonInterruptType, HexagonPcodeBackend,
    },
    errors::UnknownError,
    event_controller::{ActivateIRQnError, EventControllerImpl, InterruptExecuted},
    hooks::{CoreHandle, StyxHook},
    memory::{MemoryBackend, Mmu},
    prelude::{
        log::{info, trace, warn},
        Config, Context, ExceptionNumber,
    },
    sync::styx_async::sync::broadcast,
};

use crate::{angel, HexagonProcessorConfig};

#[derive(Default)]
pub struct HexagonVcpuEventController {
    pending: VecDeque<ExceptionNumber>,
    vid_irq_base: Option<u64>,
    // Convenience for semihosting interface
    semihosting_tx: Option<Arc<broadcast::Sender<u8>>>,
}

impl HexagonVcpuEventController {
    fn semihosting_tx(&self) -> Arc<broadcast::Sender<u8>> {
        self.semihosting_tx
            .as_ref()
            .expect("l2vic doesn't have semihosting tx!! check proc config")
            .clone()
    }
}

impl EventControllerImpl for HexagonVcpuEventController {
    /// Get the next asynchronous interrupt and execute it. Uses the async_interrupt_handler.
    fn next(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Result<InterruptExecuted, UnknownError> {
        let vid = cpu
            .read_register::<u32>(GlobalHexagonRegister::Vid)
            .unwrap();
        trace!("vcpu event controller next. VID is {vid:x}");
        match self.pending.pop_front() {
            // Get latest IRQ to run
            Some(irq) => {
                let res = async_interrupt_handler(
                    cpu,
                    mmu,
                    self.vid_irq_base.expect(
                        "Need L2vic config vid_irq_base to be set to do vcpu async interrupts",
                    ),
                    irq,
                )?;
                if let InterruptExecuted::NotExecuted = res {
                    trace!("vcpu event controller - irq {irq} not executed, putting back in queue");
                    // Put the IRQ back at the front
                    self.pending.push_front(irq);
                } else {
                    trace!("vcpu event controller - irq {irq} executed");
                }
                Ok(res)
            }

            None => Ok(InterruptExecuted::NotExecuted),
        }
    }

    fn latch(&mut self, event: ExceptionNumber) -> Result<(), ActivateIRQnError> {
        self.pending.push_back(event);
        Ok(())
    }

    /// Execute the provided interrupt number. Uses the interrupt_handler.
    /// Synchronous path.
    fn execute(
        &mut self,
        irq: ExceptionNumber,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Result<InterruptExecuted, ActivateIRQnError> {
        // These should hapen with the CPU
        if (irq == HexagonInterruptType::Sleep as i32
            || irq == HexagonInterruptType::Wake as i32
            || irq == HexagonInterruptType::ThreadStart as i32
            || irq == HexagonInterruptType::ThreadStop as i32)
        {
            info!("handling event {irq} to backend");
            cpu.handle_event(mmu, irq)
                .with_context(|| "couldn't hexagon specific to backend ")?;
            Ok(InterruptExecuted::Executed)
        } else {
            match interrupt_handler(cpu, mmu, irq, self.semihosting_tx.clone()) {
                Ok(_) => Ok(InterruptExecuted::Executed),
                Err(e) => Err(ActivateIRQnError::Unknown(e.into())),
            }
        }
    }

    fn finish_interrupt(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
    ) -> Option<ExceptionNumber> {
        trace!("finish_interrupt not implemented..");
        None
    }

    fn init(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut MemoryBackend,
        config: &mut Config,
    ) -> Result<(), UnknownError> {
        let proc_cfg = config.get::<HexagonProcessorConfig>().expect("You need to provide a hexagon process configuration in processor config to initialize vcpu interrupt controller");

        self.semihosting_tx = proc_cfg.semihosting_tx.as_ref().map(|tx| tx.clone());
        self.vid_irq_base = Some(proc_cfg.l2vic_config.vid_irq_base);
        cpu.add_hook(StyxHook::interrupt(|proc: CoreHandle, interrupt: i32| {
            // L2Vic contains the TX channel
            let semihosting_tx = proc
                .event_controller
                .get_impl::<HexagonVcpuEventController>()
                .with_context(|| "couldn't get l2vic in Styx syncrhonous interrupt handler")?
                .semihosting_tx();

            interrupt_handler(proc.cpu, proc.mmu, interrupt, Some(semihosting_tx))
        }))?;

        Ok(())
    }
}

pub fn async_interrupt_handler(
    cpu: &mut dyn CpuBackend,
    mmu: &mut Mmu,
    vid_irq_base: u64,
    interrupt_number: ExceptionNumber,
) -> Result<InterruptExecuted, UnknownError> {
    // bail if the interrupt is not pending or disabled
    let mut ipendad = Ipendad::new_with_raw_value(
        cpu.read_register::<u32>(GlobalHexagonRegister::Ipendad)
            .with_context(|| "couldn't read r0 in interrupt")?,
    );
    let iad = (ipendad.iad() >> interrupt_number) & 1;
    let ipend = (ipendad.ipend() >> interrupt_number) & 1;
    if iad == 1 || (ipend == 0) {
        warn!("interrupt not taken, as it is currently disabled/pending");
        return Ok(InterruptExecuted::NotExecuted);
    }

    // Now disable the interrupt and make it not pending
    ipendad.set_iad(ipendad.iad() & !(1 << interrupt_number));
    ipendad.set_ipend(ipendad.ipend() & !(1 << interrupt_number));

    cpu.write_register(GlobalHexagonRegister::Ipendad, ipendad.raw_value())
        .with_context(|| "couldn't write ipendad")?;

    // I am supposed to set the cause of an async interrupt (which is guaranteed to come from the l2vic)
    // to whether Vid0/1/2.. is used vid_irq_base - (irq - HexagonInterruptType::Int0) is the vid number.
    // with HexagonInterruptCause::
    let vid_num = vid_irq_base as i32 - (interrupt_number - HexagonInterruptType::Int0 as i32);
    let ssr = Ssr::new_with_raw_value(
        cpu.read_register::<u32>(HexagonRegister::Ssr)
            .with_context(|| "couldn't read ssr in interrupt")?,
    )
    .with_cause(match vid_num {
        0 => HexagonInterruptCause::Int2OrVic0,
        1 => HexagonInterruptCause::Int3OrVic1,
        2 => HexagonInterruptCause::Int4OrVic2,
        3 => HexagonInterruptCause::Int5OrVic3,
        _ => unimplemented!("cannot have more than 4 Vids in l2vic"),
    } as u8);

    cpu.write_register(HexagonRegister::Ssr, ssr.raw_value())
        .expect("couldn't get Ssr cause for async interrupt");

    interrupt_handler(cpu, mmu, interrupt_number, None)?;

    Ok(InterruptExecuted::Executed)
}

/// WARN: this should always be triggered at the end of a packet, after the pc has
/// been incremented, so the Elr should be set to the pc
///
/// This should only be done if the interrupt number is 0?
pub fn interrupt_handler(
    cpu: &mut dyn CpuBackend,
    mmu: &mut Mmu,
    interrupt_number: ExceptionNumber,
    // Only used for synchronous interrupts, so can be None in asynchronous ones.
    semihosting_tx: Option<Arc<broadcast::Sender<u8>>>,
) -> Result<(), UnknownError> {
    // Get cause, if the cause is 0 with a Trap0 call, then we need to do the angel stuff
    let ssr = Ssr::new_with_raw_value(
        cpu.read_register::<u32>(HexagonRegister::Ssr)
            .with_context(|| "couldn't read ssr in interrupt")?,
    );

    info!("interrupt number is {interrupt_number}");

    if ssr.cause() == 0 && interrupt_number == HexagonInterruptType::Trap0 as i32 {
        let swi_no = cpu
            .read_register::<u32>(HexagonRegister::R0)
            .with_context(|| "couldn't read r0 in interrupt")?;
        let arg = cpu
            .read_register::<u32>(HexagonRegister::R1)
            .with_context(|| "couldn't read r1 in interrupt")?;

        // Get semihosting tx from event controller

        angel::handle_angel(
            cpu,
            mmu,
            swi_no,
            arg,
            semihosting_tx.expect("Expected a semihosting TX for angel calls"),
        )?;

        // There are some mailboxes in trap0 that are
        // used depending on the hexagon runtime
    }

    // get evb which is the interrupt vector base
    let evb = cpu
        .read_register::<u32>(GlobalHexagonRegister::Evb)
        .with_context(|| "couldn't read interrupt vector base")?;
    let jump_point = evb + (interrupt_number * 4) as u32;

    // inspection of qemu indicates this is required
    // WARN: is this only required on _some_ synchronous interrupts?
    // see set_ssr_ex_cause for guess in target/hexagon/hex_interrupts.c

    let new_ssr = Ssr::new_with_raw_value(
        cpu.read_register::<u32>(HexagonRegister::Ssr)
            .with_context(|| "couldn't read ssr")?,
    )
    .with_ex(true);

    cpu.write_register(HexagonRegister::Ssr, new_ssr.raw_value())
        .with_context(|| "couldn't set SSR.EX = 1")?;

    info!("interrupt jumping to {jump_point:x}");

    // set elr to pc
    let pc = cpu
        .pc()
        .with_context(|| "couldn't get pc to write to elr")?;

    info!("interrupt setting elr to {pc:x}");

    // Very insidious! PC is u64
    cpu.write_register(HexagonRegister::Elr, pc as u32)
        .with_context(|| "couldn't write old pc to elr")?;

    cpu.write_register(HexagonRegister::Pc, jump_point)
        .with_context(|| "couldn't write interrupt jump point to pc")?;

    Ok(())
}
