// SPDX-License-Identifier: BSD-2-Clause
//! Stub Emulation for STM32F107

use anyhow::Context;
use derivative::Derivative;
use styx_core::{
    core::{
        builder::{BuildProcessorImplArgs, ProcessorImpl},
        ExceptionBehavior,
    },
    cpu::{
        arch::arm::{ArmRegister, ArmVariants},
        PcodeBackend,
    },
    prelude::*,
};
use styx_nvic::Nvic;
use styx_spi::{SPIController, SpiPort};
use thiserror::Error;
use tracing::{debug, info};

#[allow(unused_imports)] // stm32f107 sys
use styx_stm32f107_sys as stm32f107_sys;

pub mod example_gpio;
mod i2c;

use example_gpio::Gpio;
use i2c::I2CController;

use crate::spi::StmSpiPrecursor;
mod spi;

#[derive(Derivative)]
#[derivative(Debug, Default)]
pub struct Stm32f107Builder {
    pub exception_behavior: ExceptionBehavior,
}
// base address of each SPI port memory region
const SPI1_BASE_ADDR: u64 = 0x4001_3000;
const SPI2_BASE_ADDR: u64 = 0x4000_3800;
const SPI3_BASE_ADDR: u64 = 0x4000_3C00;

// IRQn for each SPI port
const SPI1_EVENT_IRQN: ExceptionNumber = 35;
const SPI2_EVENT_IRQN: ExceptionNumber = 36;
const SPI3_EVENT_IRQN: ExceptionNumber = 51;

impl ProcessorImpl for Stm32f107Builder {
    fn build(&self, args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError> {
        let mut cpu: Box<dyn CpuBackend> = match args.backend {
            Backend::Pcode => Box::new(PcodeBackend::new_engine_config(
                ArmVariants::ArmCortexM3,
                ArchEndian::LittleEndian,
                &args.into(),
            )),
            #[cfg(feature = "unicorn-backend")]
            Backend::Unicorn => Box::new(styx_core::cpu::UnicornBackend::new_engine_exception(
                Arch::Arm,
                ArmVariants::ArmCortexM3,
                ArchEndian::LittleEndian,
                args.exception,
            )),
            _ => return Err(BackendNotSupported(args.backend).into()),
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
        let gpio = Gpio::new();
        peripherals.push(Box::new(gpio));
        let i2c = I2CController::new();
        peripherals.push(Box::new(i2c));
        let spi = SPIController::new(vec![
            SpiPort::new(0, StmSpiPrecursor::new(SPI1_BASE_ADDR, SPI1_EVENT_IRQN)),
            SpiPort::new(1, StmSpiPrecursor::new(SPI2_BASE_ADDR, SPI2_EVENT_IRQN)),
            SpiPort::new(2, StmSpiPrecursor::new(SPI3_BASE_ADDR, SPI3_EVENT_IRQN)),
        ]);
        peripherals.push(Box::new(spi));

        Ok(ProcessorBundle {
            cpu,
            mmu,
            event_controller,
            peripherals,
            loader_hints,
        })
    }

    fn init(&self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        populate_default_registers(proc.core.cpu.as_mut(), &mut proc.core.mmu)?;

        Ok(())
    }
}

const RCC_CR_ADDR: u32 = 0x4000_0000 + 0x0002_0000 + 0x1000;
const RCC_CFGR: u32 = RCC_CR_ADDR + 0x4;

fn setup_address_space(mmu: &mut Mmu) -> Result<(), UnknownError> {
    let mut regions = Vec::new();

    // peripherals
    let peripheral_start = 0x4000_0000;
    let peripheral_size = 0x3_0000;
    regions.push(
        MemoryRegion::new(peripheral_start, peripheral_size, MemoryPermissions::all()).unwrap(),
    );

    // FSMC region
    let fsmc_start = 0xA000_0000;
    let fsmc_size = 0x1000;
    regions.push(MemoryRegion::new(fsmc_start, fsmc_size, MemoryPermissions::all()).unwrap());

    // USB OTG FS region
    let usb_otg_start = 0x5000_0000;
    let usb_otg_size = 0x4_0000;
    regions.push(MemoryRegion::new(usb_otg_start, usb_otg_size, MemoryPermissions::all()).unwrap());

    // SRAM
    let sram_start = 0x2000_0000;
    let sram_size = 96 * 1024;
    regions.push(MemoryRegion::new(sram_start, sram_size, MemoryPermissions::all()).unwrap());

    // Flash
    let flash_memory_start = 0x0800_0000;
    let flash_memory_size = 0x10_0000;
    let flash_alias_start = 0x0000_0000;

    // create the two flash regions, the real region
    // and the alias region
    let flash_region = MemoryRegion::new_with_data(
        flash_memory_start,
        flash_memory_size,
        MemoryPermissions::all(),
        vec![0xFF; flash_memory_size as usize],
    )?;
    let flash_alias = flash_region.new_alias(flash_alias_start);

    // add the flash + flash alias region
    regions.push(flash_region);
    regions.push(flash_alias);

    // add system memory
    let system_memory_start = 0x1FFF_F000;
    let system_memory_size = 0x1000;
    regions.push(
        MemoryRegion::new(
            system_memory_start,
            system_memory_size,
            MemoryPermissions::all(),
        )
        .unwrap(),
    );

    // private peripheral bus
    let private_bus_start = 0xE000_0000;
    let private_bus_size = 0x10_0000;
    regions.push(
        MemoryRegion::new(
            private_bus_start,
            private_bus_size,
            MemoryPermissions::READ | MemoryPermissions::WRITE,
        )
        .unwrap(),
    );

    // TODO: add:
    // external ram 0x6000_0000 - 0x9FFF_FFFF
    // memory mapped peripherals 0xE010_0000 - 0xFFFF_FFFF

    // map the memory into the backend
    while let Some(region) = regions.pop() {
        mmu.add_memory_region(region)?;
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
    size: u32,
    value: &[u8],
) -> Result<(), UnknownError> {
    let hse_ready: [u8; 4] = 0x0002_0000_u32.to_le_bytes();
    let pll_ready: [u8; 4] = 0x0200_0000_u32.to_le_bytes();
    debug_assert_eq!(size, 4);
    let value = u32::from_le_bytes(value[0..4].try_into().unwrap());

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
    size: u32,
    value: &[u8],
) -> Result<(), UnknownError> {
    let pll_on: [u8; 4] = 0x0000_0008_u32.to_le_bytes();
    debug_assert_eq!(size, 4);
    let value = u32::from_le_bytes(value[0..4].try_into().unwrap());

    debug!("CFGR WRITE CALLBACK, value: {value:#08X?}");
    if (value & 0x2) > 0 {
        info!("Setting RCC->CFGR to 0x0000_0008");
        proc.mmu.data().write(RCC_CFGR).bytes(&pll_on)?;
    }
    Ok(())
}
