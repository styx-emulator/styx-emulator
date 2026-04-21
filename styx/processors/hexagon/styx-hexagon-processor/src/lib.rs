// SPDX-License-Identifier: BSD-2-Clause
//! # Styx-Processors

use event_controller::HexagonEventController;
use styx_core::arch::hexagon::register_fields::Ssr;
use styx_core::arch::hexagon::HexagonRegister;
use styx_core::cpu::arch::hexagon::HexagonVariants;
use styx_core::cpu::{Arch, Backend};
use styx_core::loader::LoaderHints;
use styx_core::memory::physical::PhysicalMemoryVariant;
use styx_core::memory::{MemoryBackend, MemoryPermissions, Mmu};
use styx_core::prelude::{Context, Peripheral};
use styx_core::{
    core::{
        builder::{BuildProcessorImplArgs, ProcessorImpl},
        ProcessorBundle,
    },
    cpu::{ArchEndian, CpuBackendExt, HexagonPcodeBackend},
    errors::{anyhow, UnknownError},
    hooks::{CoreHandle, Hookable, Resolution, StyxHook},
};
use tlb::HexagonTlb;

mod event_controller;
mod exception;
mod tlb;

#[derive(serde::Deserialize)]
pub struct HexagonBuilder {
    pub variant: HexagonVariants,
}

impl Default for HexagonBuilder {
    fn default() -> Self {
        Self {
            variant: HexagonVariants::QDSP6V62,
        }
    }
}

impl ProcessorImpl for HexagonBuilder {
    fn build(&self, args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError> {
        let mut cpu = if let Backend::Pcode = args.backend {
            Box::new(HexagonPcodeBackend::new_engine_config(
                self.variant.clone(),
                ArchEndian::LittleEndian,
                &args.into(),
            ))
        } else {
            return Err(anyhow::anyhow!(
                "hexagon processor only supports pcode backend"
            ));
        };

        // WARN: this should always be triggered at the end of a packet, after the pc has
        // been incremented, so the Elr should be set to the pc
        let interrupt_handler = |handle: CoreHandle, interrupt_number: i32| {
            // get cause, if the cause is 0 then we need to do the angel stuff
            let ssr = Ssr::new_with_raw_value(
                handle
                    .cpu
                    .read_register::<u32>(HexagonRegister::Ssr)
                    .with_context(|| "couldn't read ssr in interrupt")?,
            );

            if ssr.cause() == 0 {
                let swi_no = handle
                    .cpu
                    .read_register::<u32>(HexagonRegister::R0)
                    .with_context(|| "couldn't read r0 in interrupt")?;
                let arg = handle
                    .cpu
                    .read_register::<u32>(HexagonRegister::R1)
                    .with_context(|| "couldn't read r1 in interrupt")?;

                if swi_no == 0x43 {
                    print!("{}", arg as u8 as char);
                }
            }

            // get evb which is the interrupt vector base
            let evb = handle
                .cpu
                .read_register::<u32>(HexagonRegister::Evb)
                .with_context(|| "couldn't read interrupt vector base")?;
            let jump_point = evb + (interrupt_number * 4) as u32;

            info!("interrupt jumping to {:x}", jump_point);

            // set elr to pc
            let pc = handle
                .cpu
                .pc()
                .with_context(|| "couldn't get pc to write to elr")?;

            info!("interrupt setting elr to {:x}", pc);

            handle
                .cpu
                .write_register(HexagonRegister::Elr, pc)
                .with_context(|| "couldn't write old pc to elr")?;
            handle
                .cpu
                .write_register(HexagonRegister::Pc, jump_point)
                .with_context(|| "couldn't write interrupt jump point to pc")?;

            Ok(())
        };

        cpu.add_hook(StyxHook::interrupt(interrupt_handler))?;

        let memory = match self.variant {
            HexagonVariants::QDSP6V62 => MemoryBackend::new(PhysicalMemoryVariant::FlatMemory),
            _ => {
                return Err(UnknownError::msg(
                    "hexagon variant {self.variant:?} is not supported, only v62 is supported",
                ))
            }
        };

        let l2vic = Box::new(L2Vic::default());

        let peripherals: Vec<Box<dyn Peripheral>> = Vec::new();

        let mut hints = LoaderHints::new();
        hints.insert("arch".to_string().into_boxed_str(), Box::new(Arch::Hexagon));

        Ok(ProcessorBundle {
            cpu,
            tlb: Box::new(HexagonTlb::new()),
            memory,
            event_controller: l2vic,
            peripherals,
            loader_hints: hints,
        })
    }
}
