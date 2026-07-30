// SPDX-License-Identifier: BSD-2-Clause

use std::sync::Arc;

use styx_core::{
    arch::hexagon::{register_fields::Ssr, HexagonRegister},
    cpu::{CpuBackend, CpuBackendExt},
    errors::UnknownError,
    event_controller::{ActivateIRQnError, InterruptExecuted, Peripherals},
    hooks::{CoreHandle, StyxHook},
    memory::{MemoryBackend, Mmu},
    prelude::{
        log::{info, trace},
        Config, Context, EventControllerImpl, ExceptionNumber,
    },
    sync::styx_async::sync::broadcast,
};

use crate::{angel::handle_angel, HexagonProcessorConfig};

#[derive(Default)]
pub struct HexagonEventController {
    semihosting_tx: Option<Arc<broadcast::Sender<u8>>>,
}

impl HexagonEventController {
    fn semihosting_tx(&self) -> Arc<broadcast::Sender<u8>> {
        self.semihosting_tx
            .as_ref()
            .expect("hexagon event controller doesn't have semihosting tx!! check proc config")
            .clone()
    }
}

impl EventControllerImpl for HexagonEventController {
    fn next(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _peripherals: &mut Peripherals,
    ) -> Result<InterruptExecuted, UnknownError> {
        trace!("event controller next unimplemented");
        Ok(InterruptExecuted::NotExecuted)
    }

    fn latch(&mut self, _event: ExceptionNumber) -> Result<(), ActivateIRQnError> {
        todo!()
    }

    fn execute(
        &mut self,
        _irq: ExceptionNumber,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
    ) -> Result<InterruptExecuted, ActivateIRQnError> {
        todo!()
    }

    fn finish_interrupt(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
    ) -> Option<ExceptionNumber> {
        todo!()
    }

    fn init(
        &mut self,
        cpu: &mut dyn CpuBackend,
        _mmu: &mut MemoryBackend,
        config: &mut Config,
    ) -> Result<(), UnknownError> {
        trace!("the hexagon event controller has started");

        let proc_cfg = config.get::<HexagonProcessorConfig>().expect("You need to provide a hexagon process configuration in processor config to initialize l2vic");

        // This should always be triggered at the end of a packet (see `HexagonPcodeBackend` implementation,
        // specifically details about the `DelayedInterrupt`, for more information), after the pc has
        // been incremented, so at this point, the Elr register will be set to the pc to return to.
        //
        // FIXME: multicore
        self.semihosting_tx = proc_cfg.semihosting_tx.as_ref().map(|tx| tx.clone());
        let interrupt_handler = |handle: CoreHandle, interrupt_number: i32| {
            // get cause, if the cause is 0 then we need to do the angel stuff
            let ssr = Ssr::new_with_raw_value(
                handle
                    .cpu
                    .read_register::<u32>(HexagonRegister::Ssr)
                    .with_context(|| "couldn't read ssr in interrupt")?,
            );

            // SSR.CAUSE equals 0 implies that we must handle ANGEL calls
            // See QUIC QEMU's (branch hex-next) file target/hexagon/hexswi.c,
            // specifically the case for HEX_EVENT_TRAP0 in
            // hex_cpu_do_interrupt.
            if ssr.cause() == 0 {
                let swi_no = handle
                    .cpu
                    .read_register::<u32>(HexagonRegister::R0)
                    .with_context(|| "couldn't read r0 in interrupt")?;
                let arg = handle
                    .cpu
                    .read_register::<u32>(HexagonRegister::R1)
                    .with_context(|| "couldn't read r1 in interrupt")?;
                // event controller contains the TX channel
                let semihosting_tx = handle
                    .event_controller
                    .get_impl::<HexagonEventController>()
                    .with_context(|| "couldn't get l2vic in Styx syncrhonous interrupt handler")?
                    .semihosting_tx();

                handle_angel(handle.cpu, handle.mmu, swi_no, arg, semihosting_tx)
                    .expect("angel call failed");
            }

            // get evb which is the interrupt vector base
            let evb = handle
                .cpu
                .read_register::<u32>(HexagonRegister::Evb)
                .with_context(|| "couldn't read interrupt vector base")?;
            let jump_point = evb + (interrupt_number * 4) as u32;

            info!("interrupt jumping to {jump_point:x}");

            // set elr to pc
            let pc = handle
                .cpu
                .pc()
                .with_context(|| "couldn't get pc to write to elr")?;

            info!("interrupt setting elr to {pc:x}");

            handle
                .cpu
                .write_register(HexagonRegister::Elr, pc as u32)
                .with_context(|| "couldn't write old pc to elr")?;
            handle
                .cpu
                .write_register(HexagonRegister::Pc, jump_point)
                .with_context(|| "couldn't write interrupt jump point to pc")?;

            Ok(())
        };

        cpu.add_hook(StyxHook::interrupt(interrupt_handler))?;

        Ok(())
    }
}
