// SPDX-License-Identifier: BSD-2-Clause
//! # Styx-Processors

use l2vic::L2Vic;
use qtimer::QTimer;
use styx_core::arch::hexagon::HexagonRegister;
use styx_core::cpu::arch::hexagon::HexagonVariants;
use styx_core::cpu::{Arch, Backend, CpuBackend, CpuBackendExt, PcodeBackendConfiguration};
use styx_core::hooks::CoreHandle;
use styx_core::loader::LoaderHints;
use styx_core::memory::physical::PhysicalMemoryVariant;
use styx_core::prelude::log::info;
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
mod cfgtable;
mod config;
mod exception;
mod l2vic;
mod qtimer;
mod tlb;

pub use cfgtable::*;
pub use config::*;

const SUBSYSTEM_CFGTABLE_OFFSET: u64 = 0x8;
const JTLB_ENTRIES_CFGTABLE_OFFSET: u64 = 0x2c;

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

        // Set cfgbase
        let proc_config = args
            .config
            .get::<HexagonProcessorConfig>()
            .expect("expected Hexagon processor config during build");
        cpu.write_register(HexagonRegister::CfgBase, (proc_config.cfgbase >> 16) as u32)
            .expect("Couldn't write config table for hexagon");

        // Set subsystem base
        write_cfgtable_field(
            cpu.as_mut(),
            &mut memory,
            SUBSYSTEM_CFGTABLE_OFFSET,
            (proc_config.subsystem_base >> 16) as u32,
        );
        write_cfgtable_field(
            cpu.as_mut(),
            &mut memory,
            JTLB_ENTRIES_CFGTABLE_OFFSET,
            proc_config.tlb_entries,
        );

        // Setup cfgtable (cfgbase is written in HexagonBuilder)
        for (cfgbase_entry, value) in proc_config.config_table.iter() {
            write_cfgtable_field(cpu.as_mut(), &mut memory, *cfgbase_entry as u64, *value);
        }

        let peripherals: Vec<Box<dyn Peripheral>> = Vec::new();

        // Peripherals may use this
        memory
            .memory_map(0x100000000, 0x40000000, MemoryPermissions::all())
            .with_context(|| "couldn't add memory region for peripherals")?;

        let l2vic = Box::new(L2Vic::default());

        let peripherals: Vec<Box<dyn Peripheral>> = vec![Box::new(QTimer::default())];

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
/// Note: physical memory addresses on Hexagon are 36 bits.
///
/// The register `cfgbase`'s _lower_ 20 bits correspond to the upper 20 bits (bits 17 to 36)
/// of the config table's physical address. See QUIC QEMU's include/hw/hexagon/hexagon.h, specifically the
/// `hexagon_config_table` struct for details what this table looks like.
///
/// To access the config table, we must use the memw_phys instruction. The instruction
/// is a bit confusing. The instruction takes two parameters, `Rs` and `Rt`, like this: `memw_phys(Rs, Rt)`.
/// `Rt << 5` makes up the high 25 bits of the PA, and Rs's lowest 11 bits
/// make up the low 11 bits of the PA.
///
/// See 11.9.2 "Load from physical address" for more info.
///
/// In order to take the upper 20 bits of `cfgbase` and turn it into something that we can feed into `memw_phys`,
/// we shift the `cfgbase` value left by 5 bits into `Rt` and have the lower 11 bits of `Rs` be the offset
/// into the table structure.
///
/// As a clearer example, maybe cfgbase is 0x0000afaf. This refers to a
/// config table starting at address 0x0afaf0000 (36 bit PA). We want to get the fastl2vic base.
/// According to `struct hexagon_config_table`, the offset in the table for the fastl2vic base is
/// 0x28. Therefore we set Rs to 0x28, and Rt to (0xafaf << 5).
///
/// Note: Table entries that are a peripheral base are encoded the same way as how `cfgbase` is encoded
/// exactly like how the `cfgbase` register does. For debugging, you will have to shift this entry left by 16
/// to get the base physical address of whatever peripheral/thing you're looking for. For access a peripheral through
/// `memw_phys`, follow the process described above.
///
/// Note: entries not corresponding to a memory address (eg. `jtlb_size_entries`) don't have to be shifted.
///
/// This function takes an offset into the config table (eg. `0x28` like before)
/// and reads cfgbase to find the value in the config table at that offset. The result from this
/// function are not shifted, as not all entries in the config
/// table are addresses.
pub fn read_cfgtable_field(
    cpu: &mut dyn CpuBackend,
    mmu: &mut Mmu,
    offset: u64,
) -> Result<u32, UnknownError> {
    let cfgbase = cpu
        .read_register::<u32>(HexagonRegister::CfgBase)
        .with_context(|| "couldn't read cfgbase")? as u64;

    let cfgtable_offset_addr: u64 = (cfgbase << 16) + offset;
    mmu.read_u32_le_phys_data(cfgtable_offset_addr)
        .with_context(|| "couldn't read offset from cfg table")
}

pub fn write_cfgtable_field(
    cpu: &mut dyn CpuBackend,
    mmu: &mut MemoryBackend,
    offset: u64,
    value: u32,
) {
    let cfgbase = cpu
        .read_register::<u32>(HexagonRegister::CfgBase)
        .expect("Couldn't read cfgbase")
        << 16;

    let periph_loc = cfgbase as u64 + offset;

    info!(
        "writing periph loc {periph_loc:x} value {:x?}",
        value.to_le_bytes()
    );

    mmu.write_data(periph_loc, &value.to_le_bytes())
        .unwrap_or_else(|_| panic!("couldn't set peripheral base at {offset:x}"))
}
