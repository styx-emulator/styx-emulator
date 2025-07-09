// SPDX-License-Identifier: BSD-2-Clause
//! Stub emulation for the STM32F405 processor
#![allow(non_upper_case_globals)]
use anyhow::Context;
use styx_core::core::builder::BuildProcessorImplArgs;
use styx_core::cpu::{PcodeBackend, UnicornBackend};
use styx_core::prelude::*;
use styx_core::{
    core::builder::ProcessorImpl,
    cpu::arch::{
        arm::{ArmRegister, ArmVariants},
        backends::ArchVariant,
    },
};
use styx_nvic::Nvic;
use styx_peripherals::uart::UartController;
use thiserror::Error;
use tracing::{debug, info};
use uart::get_uarts;

mod dma;
mod uart;

// helper tuple typedef for human-readable const address map
type RegionInfo = (
    &'static str,      // name of region
    u64,               // base address of region
    u64,               // size of region
    MemoryPermissions, // permissions for region
    Option<u8>,        // initialization of region
    Option<u64>,       // alias offset
);

const MiB: u64 = 1024 * 1024;
const KiB: u64 = 1024;
const RWX: MemoryPermissions = MemoryPermissions::all();
const RW: MemoryPermissions = MemoryPermissions::RW;

/// Address map for the STM32F405. The whole address space is 4GB in size.
/// **[STM32F405xx: Memory Mapping: Figure 18 and Table 10](https://www.st.com/resource/en/datasheet/dm00037051.pdf#page=71)**
/// describes the complete memory mapping.
#[allow(clippy::identity_op)]
#[rustfmt::skip]
const ADDRESS_MAP: [RegionInfo; 13] = [
    // The Boot Region takes up the initial 1MiB of the address space. It is bit-band aliased
    // to either Flash memory, system memory, or data SRAM depending on how the BOOT pins are set.
    ("BOOT",	        0x0000_0000,	1*MiB,               RWX, None, None),

    // Flash memory
    ("FLASH",           0x0800_0000,	1*MiB,               RWX, None, None),

    // 64 KiB auxillary SRAM memory
    ("SRAM3",	        0x1000_0000,	64*KiB,              RWX, None, None),

    // System memory (note: this lumps in some reserved memory and Option bytes)
    ("SYS_MEM",	        0x1FFF_0000,	64*KiB,              RWX, None, None),

    // 112 KiB main SRAM
    ("SRAM1",	        0x2000_0000,	112*KiB,             RWX, None, None),

    // 16 KiB auxillary SRAM memory
    ("SRAM2",	        0x2001_C000,	16*KiB,              RWX, None, None),

    // Peripherals take up the next 512 MiB (note: to better fit page size
    // constraints, the entire memory block is abstracted over for now)
    ("PERIPHERALS",	    0x4000_0000,    512*MiB,             RW, None, None),

    // FSMC
    ("FSMC_BANK_1",	    0x6000_0000,	256*MiB,             RW, None, None),
    ("FSMC_BANK_2",	    0x7000_0000,	256*MiB,             RW, None, None),
    ("FSMC_BANK_3",	    0x8000_0000,	256*MiB,             RW, None, None),
    ("FSMC_BANK_4",	    0x9000_0000,	256*MiB,             RW, None, None),
    ("FSMC_CTRL",	    0xA000_0000,	4*KiB,               RW, None, None),

    // Cortex-M4 internal peripherals
    ("CORTEX_M4",	    0xE000_0000,	1*MiB,               RW, None, None),
];

// Errors for STM32F405
#[derive(Debug, Error)]
pub enum Stm32f405Error {
    #[error("Loader `{0}` is incompatible with K21 implementation")]
    IncompatibleLoader(&'static str),
    #[error("Path is not valid: {0}")]
    InvalidFirmwarePath(String),
    #[error("Expected `{0}` memory regions, loader returned: `{1}`")]
    InvalidMemoryRegionCount(usize, usize),
    #[error("`{0:?}` is not a valid Architecture Variant for the K21 implementation")]
    InvalidVariant(ArchVariant),
    #[error("No loaded region starts at necessary location")]
    MissingProgramStartRegion,
}

impl From<Stm32f405Error> for StyxMachineError {
    fn from(value: Stm32f405Error) -> Self {
        Self::TargetSpecific(Box::new(value))
    }
}

#[derive(Debug, Default)]
pub struct Stm32f405Builder {}

impl ProcessorImpl for Stm32f405Builder {
    fn build(&self, args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError> {
        let mut cpu: Box<dyn CpuBackend> = match args.backend {
            Backend::Pcode => Box::new(PcodeBackend::new_engine_config(
                ArmVariants::ArmCortexM4,
                ArchEndian::LittleEndian,
                &args.into(),
            )),
            Backend::Unicorn => Box::new(UnicornBackend::new_engine_exception(
                Arch::Arm,
                ArmVariants::ArmCortexM4,
                ArchEndian::LittleEndian,
                args.exception,
            )),
        };

        let mut mmu = Mmu::default_region_store();
        // nvic event controller
        let event_controller = Box::new(Nvic::default());
        let mut loader_hints = LoaderHints::new();
        loader_hints.insert("arch".to_string().into_boxed_str(), Box::new(Arch::Arm));

        setup_address_space(&mut mmu)?;
        set_hooks(cpu.as_mut())?;

        // setup the peripherals
        let mut peripherals: Vec<Box<dyn Peripheral>> = Vec::new();
        let uart = UartController::new(get_uarts());
        peripherals.push(Box::new(uart));

        Ok(ProcessorBundle {
            cpu,
            mmu,
            event_controller,
            peripherals,
            loader_hints,
        })
    }

    fn init(&self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        populate_default_registers(proc.core.cpu.as_mut(), &mut proc.core.mmu)
    }
}

const RCC_CR_ADDR: u32 = 0x4000_0000 + 0x0002_0000 + 0x3800;
const RCC_CFGR: u32 = RCC_CR_ADDR + 0x8;

fn set_hooks(cpu: &mut dyn CpuBackend) -> Result<(), UnknownError> {
    // Setup the PLL setup + init hooks
    // rcc_cr
    cpu.add_hook(StyxHook::memory_write(
        RCC_CR_ADDR as u64,
        rcc_cr_pass_callback,
    ))?;

    // rcc_cfgr
    cpu.add_hook(StyxHook::memory_write(
        RCC_CFGR as u64,
        rcc_cfgr_pass_callback,
    ))?;

    Ok(())
}
/// fakes the RCC cr acknowledging the memory writes
fn rcc_cr_pass_callback(
    proc: CoreHandle,
    _address: u64,
    _size: u32,
    value: &[u8],
) -> Result<(), UnknownError> {
    let hse_ready: [u8; 4] = 0x0002_0000_u32.to_le_bytes();
    let pll_ready: [u8; 4] = 0x0200_0000_u32.to_le_bytes();
    let value = u64::from_le_bytes(value[0..8].try_into().unwrap());

    debug!("CR WRITE CALLBACK, value: {value:#08X?}");
    if (value & 0x1_0000) > 0 {
        info!("Setting RCC->CR to 0x0002_0000");
        proc.mmu.data().write(RCC_CR_ADDR).bytes(&hse_ready)?;
    } else if (value & 0x01000000) > 0 {
        info!("Setting RCC->CR to 0x0200_0000");
        proc.mmu.data().write(RCC_CR_ADDR).bytes(&pll_ready)?;
    }
    Ok(())
}

fn rcc_cfgr_pass_callback(
    proc: CoreHandle,
    _address: u64,
    _size: u32,
    value: &[u8],
) -> Result<(), UnknownError> {
    let pll_on: [u8; 4] = 0x0000_0008_u32.to_le_bytes();
    let value = u64::from_le_bytes(value[0..8].try_into().unwrap());

    debug!("CFGR WRITE CALLBACK, value: {value:#08X?}");
    if (value & 0x2) > 0 {
        info!("Setting RCC->CFGR to 0x0000_0008");
        proc.mmu.data().write(RCC_CFGR).bytes(&pll_on)?;
    }
    Ok(())
}

#[derive(Debug, Error)]
#[error("no loaded region starts at necessary location")]
pub struct MissingProgramStartRegion;

// need to set
// - SP u32 from address 0
// - PC u32 from address 4
fn populate_default_registers(cpu: &mut dyn CpuBackend, mmu: &mut Mmu) -> Result<(), UnknownError> {
    // find the regions available that starts at address 0 or address 0x0800_0000
    // (either of the flash or the flash alias region)
    for region in mmu.regions().context("must have region mmu")? {
        if region.base() == 0x0 || region.base() == 0x0800_0000 {
            // found a base region, read the first 8 bytes to get the register
            // values to use
            let sp = u32::from_le_bytes(region.data[0..4].try_into().unwrap());
            let pc = u32::from_le_bytes(region.data[4..8].try_into().unwrap());

            log::debug!(
                "populating default registers from 0x{:X}: sp=0x{sp:X}, pc=0x{pc:X}",
                region.base()
            );
            cpu.write_register(ArmRegister::Sp, sp)?;
            cpu.write_register(ArmRegister::Pc, pc)?;

            return Ok(());
        }
    }

    // did not find the flash region which has starting pc
    Err(MissingProgramStartRegion.into())
}

fn setup_address_space(mmu: &mut Mmu) -> Result<(), UnknownError> {
    macro_rules! debug_region {
        ($name: expr, $base: expr, $size: expr, $init: expr, $alias_base: expr, $perms: expr) => {
            let __alias = match $alias_base {
                Some(b) => format!("A({:#010x})", b),
                None => String::from("-"),
            };
            let __initialized = match $init {
                Some(b) => format!("{:#x}", b),
                None => String::from("-"),
            };
            debug!(
                "Memory Region: {:20} {:#010x} {:12} {} {:5} {:13}",
                $name, $base, $size, $perms, __initialized, __alias,
            )
        };
    }

    let mut regions = Vec::new();

    for rg in ADDRESS_MAP.iter() {
        #[allow(dead_code)]
        let (name, base, size, perms, init, alias_base) = *rg;
        debug_region!(name, base, size, init, alias_base, perms);
        let region = match init {
            // Initialize region
            Some(i) => MemoryRegion::new_with_data(base, size, perms, vec![i; size as usize]),
            // do not initialize region
            None => MemoryRegion::new(base, size, perms),
        }?;

        // create alias as specified...
        if let Some(addr) = alias_base {
            let alias = region.new_alias(addr);
            regions.push(alias);
        }
        regions.push(region);
    }

    // add all regions to cpu
    let nregions = regions.len();
    while let Some(region) = regions.pop() {
        mmu.add_memory_region(region)?;
    }
    debug!(
        "setup_address_space: added {} memory regions to the cpu",
        nregions
    );
    Ok(())
}
