// SPDX-License-Identifier: BSD-2-Clause
//! # Styx-Processors

use l2vic::L2Vic;
use qtimer::QTimer;
use styx_core::arch::hexagon::register_fields::Ssr;
use styx_core::arch::hexagon::HexagonRegister;
use styx_core::cpu::arch::hexagon::HexagonVariants;
use styx_core::cpu::{Arch, Backend, CpuBackend, PcodeBackendConfiguration};
use styx_core::loader::LoaderHints;
use styx_core::memory::physical::PhysicalMemoryVariant;
use styx_core::memory::{MemoryPermissions, Mmu};
use styx_core::prelude::log::info;
use styx_core::prelude::{Context, Peripheral};
use styx_core::{
    core::{
        builder::{BuildProcessorImplArgs, ProcessorImpl},
        ProcessorBundle,
    },
    cpu::{ArchEndian, CpuBackendExt, HexagonInterruptType, HexagonPcodeBackend},
    errors::{anyhow, UnknownError},
    hooks::{CoreHandle, Hookable, Resolution, StyxHook},
};
use tlb::HexagonTlb;

mod exception;
mod l2vic;
mod qtimer;
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
                &PcodeBackendConfiguration {
                    register_read_hooks: false,
                    register_write_hooks: true,
                    exception: args.exception,
                },
            ))
        } else {
            return Err(anyhow::anyhow!(
                "hexagon processor only supports pcode backend"
            ));
        };

        // WARN: this should always be triggered at the end of a packet, after the pc has
        // been incremented, so the Elr should be set to the pc
        //
        // This should only be done if the interrupt number is 0?
        let interrupt_handler = |handle: CoreHandle, interrupt_number: i32| {
            // get cause, if the cause is 0 then we need to do the angel stuff
            let ssr = Ssr::new_with_raw_value(
                handle
                    .cpu
                    .read_register::<u32>(HexagonRegister::Ssr)
                    .with_context(|| "couldn't read ssr in interrupt")?,
            );

            info!("interrupt number is {}", interrupt_number);

            if ssr.cause() == 0 && interrupt_number == HexagonInterruptType::Trap0 as i32 {
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

        let mut mmu = match self.variant {
            HexagonVariants::QDSP6V62 => Mmu::new(
                Box::new(HexagonTlb::new()),
                PhysicalMemoryVariant::RegionStore,
                cpu.as_mut(),
            )?,
            _ => {
                return Err(UnknownError::msg(
                    "hexagon variant {self.variant:?} is not supported, only v62 is supported",
                ))
            }
        };

        mmu.memory_map(0, 2u64.pow(32), MemoryPermissions::all())?;

        let l2vic = Box::new(L2Vic::default());

        let peripherals: Vec<Box<dyn Peripheral>> = vec![Box::new(QTimer::default())];

        let mut hints = LoaderHints::new();
        hints.insert("arch".to_string().into_boxed_str(), Box::new(Arch::Hexagon));

        Ok(ProcessorBundle {
            cpu,
            mmu,
            event_controller: l2vic,
            peripherals,
            loader_hints: hints,
        })
    }
}

/// Hexagon's cfgbase register contains a table with various information that
/// eventually allows us to retreive information on peripherals.
///
/// The way to do this is to read cfgbase (containing 20 bits of
/// memory address information), shift it left by 5 (yielding the high 25 bits),
/// and then add a (table) offset of (10 bits) and read that 36-bit physical address
/// using memw_phys.
///
/// As a clearer example, maybe cfgbase is 0xafaf. This refers to a
/// config table starting at address 0x0afaf0000 (36 bits).
///
/// To get this, we shift the 20 bits (0x0afaf << 5). Now, the memw_phys
/// instruction reads with two parameters: memw_phys(Rs, Rt) (there is also an
/// output register, but not relevant for us).
///
/// The QEMU Hexagon tests that use the config table call
/// memw_phys where Rt register holds (0x0afaf << 5).
///
/// The memw_phys instruction accesses the address by using Rt's value as bits 11 to 35 (zero indexed)
/// of the PA and bits 0 to 10 as Rs.  Therefore we have the high bits as ((0x0afaf) << 5) << 11
/// which is just 0x0afaf << 16, or 0x0afaf0000, and the Rs value is the offset into the table.
///
/// Each table entry contains a similar 20-bit value corresponding to a physical address
/// for the entry. Eg. the "subsystem base" offset will contain a 20-bit value
/// corresponding to the base of various peripheral configuration registers.
///
/// This function takes an offset and uses cfgbase to find the value in the config
/// table at that offset.
pub fn read_cfgtable_field(
    cpu: &mut dyn CpuBackend,
    mmu: &mut Mmu,
    offset: u64,
) -> Result<u32, UnknownError> {
    let cfgbase = cpu
        .read_register::<u32>(HexagonRegister::CfgBase)
        .with_context(|| "couldn't read cfgbase")? as u64;

    let cfgtable_offset_addr: u64 = (cfgbase << 16) + offset;
    Ok(mmu
        .read_u32_le_phys_data(cfgtable_offset_addr)
        .with_context(|| "couldn't read offset from cfg table")?)
}
