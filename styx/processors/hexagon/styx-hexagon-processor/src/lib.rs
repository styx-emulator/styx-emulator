// SPDX-License-Identifier: BSD-2-Clause
//! # Styx-Processors

use clade::Clade;
use l2vic::L2Vic;
use qtimer::QTimer;
use styx_core::arch::hexagon::HexagonRegister;
use styx_core::cpu::arch::hexagon::HexagonVariants;
use styx_core::cpu::{Arch, Backend, CpuBackend, PcodeBackendConfiguration};
use styx_core::hooks::CoreHandle;
use styx_core::loader::LoaderHints;
use styx_core::memory::physical::PhysicalMemoryVariant;
use styx_core::memory::{MemoryBackend, MemoryPermissions, MemoryRegion, Mmu};
use styx_core::prelude::{Context, Peripheral};
use styx_core::{
    core::{
        builder::{BuildProcessorImplArgs, ProcessorImpl},
        ProcessorBundle,
    },
    cpu::{ArchEndian, CpuBackendExt, HexagonPcodeBackend},
    errors::{anyhow, UnknownError},
    hooks::{Hookable, StyxHook},
};
use tlb::HexagonTlb;

mod angel;
mod clade;
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
                    register_read_hooks: true,
                    register_write_hooks: true,
                    exception: args.exception,
                },
            ))
        } else {
            return Err(anyhow::anyhow!(
                "hexagon processor only supports pcode backend"
            ));
        };

        cpu.add_hook(StyxHook::interrupt(|proc: CoreHandle, interrupt: i32| {
            l2vic::interrupt_handler(proc.cpu, proc.mmu, interrupt)
        }))?;

        let mut memory = match self.variant {
            HexagonVariants::QDSP6V62 => MemoryBackend::new(PhysicalMemoryVariant::FlatMemory),
            _ => {
                return Err(UnknownError::msg(
                    "hexagon variant {self.variant:?} is not supported, only v62 is supported",
                ))
            }
        };

        // Peripherals may use this
        memory
            .memory_map(0x100000000, 0x40000000, MemoryPermissions::all())
            .with_context(|| "couldn't add memory region for peripherals")?;

        let l2vic = Box::new(L2Vic::default());

        let peripherals: Vec<Box<dyn Peripheral>> =
            vec![Box::new(QTimer::default()), Box::new(Clade::default())];

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
