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
//! Generic support for the NXP K21 Family
//!
//! This should provide a good enough starting point for the K21
//! family, and should be trivial to adapt to the specific needs.
//!
//! The deciphering of chip name to human readable stream can be
//! broken down in the following table:
//!
#![cfg_attr(feature = "docimages",
cfg_attr(all(),
doc = ::embed_doc_image::embed_image!("k21partbreakdown", "assets/k21partbreakdown.png"),))]
#![cfg_attr(
    not(feature = "docimages"),
    doc = "**Doc images not enabled**. Compile with feature `docimages` and Rust version >= 1.54 \
           to enable."
)]
//!
//! ![k21parttable][k21partbreakdown]
//!
//! This translates the name `MK21FN1M0VMC12` into:
//!
//! |  Field  | Meaning                              |
//! |---------|--------------------------------------|
//! | M       | Public release                       |
//! | K21     | K21 Family                           |
//! | F       | Cortex-M4 with DSP and FPU           |
//! | N       | Program Flash only                   |
//! | 1M0     | 1MB Program Flash                    |
//! | (blank) | Main release                         |
//! | V       | -40C to 105C operating temperature   |
//! | MC      | 121 MAPBGA package                   |
//! | 12      | 120MHz CPU frequency                 |
//! | (blank) | Tray packaging                       |
//!
//! This library contains a [`Kinetis21Builder`] struct that takes a
//! [`K21Variant`] and a path to the firmware to load on the core.
use bit_banding::BitBands;
use styx_core::core::builder::{BuildProcessorImplArgs, ProcessorImpl};
use styx_core::cpu::arch::arm::{ArmRegister, ArmVariants};
use styx_core::cpu::{PcodeBackend, UnicornBackend};
use styx_core::errors::anyhow::anyhow;
use styx_core::memory::memory_region::MemoryRegion;
use styx_core::prelude::*;
use styx_mk21f12_sys as mk21f12_sys;
use styx_nvic::Nvic;
use thiserror::Error;

// this import is only used when building documentation. When the
// rust issue https://github.com/rust-lang/rust/issues/32104 is resolved
// then we can drop this crate
#[allow(unused_imports)]
#[cfg(feature = "docimages")]
use embed_doc_image::embed_doc_image;

use self::ftm::FtmController;
use self::mcg::Mcg;
use self::systick::SysTickTimer;
use self::uart::get_uarts;

use styx_peripherals::uart::UartController;

mod bit_banding;
mod ftm;
pub mod gpio;
mod mcg;
mod systick;
mod uart;

use gpio::Gpio;

/// Error container for the Kinetis 21 tree
#[derive(Debug, Error)]
pub enum Kinetis21Error {
    #[error("Loader `{0}` is incompatible with K21 implementation")]
    IncompatibleLoader(&'static str),
    #[error("Path is not valid: {0}")]
    InvalidFirmwarePath(String),
    #[error("Firmware loader returned `{0}` regions when `{1}` was expected")]
    InvalidMemoryRegionCount(usize, usize),
    #[error("`{0:?}` is not a valid Architecture Variant for the K21 implementation")]
    InvalidVariant(ArchVariant),
    #[error("No loaded region starts at necessary location")]
    MissingProgramStartRegion,
}

/// Variant selector for the Kinetis 21 Tree
#[derive(Debug)]
pub enum K21Variant {
    MK21FN1M0VMC12, // default variant, the model with all the features
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
pub enum K21PeripheralId {
    UartController,
    Uart0,
    Uart1,
    Uart2,
    Uart3,
    Uart4,
    Uart5,
}

#[derive(Default)]
pub struct Kinetis21Builder {}

impl ProcessorImpl for Kinetis21Builder {
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

        self.setup_address_space(&mut mmu)?;

        // Note: BitBands is unique in that its logic is owned by the Arcs
        // contained in its callbacks. It is not owned by the EventManager
        // or the Processor.
        BitBands::default()
            .add_band(0x2000_0000..0x2010_0000, 0x2200_0000)
            .add_band(0x4000_0000..0x4010_0000, 0x4200_0000)
            .register_hooks(cpu.as_mut())?;

        let peripherals: Vec<Box<dyn Peripheral>> = vec![
            Box::new(SysTickTimer::new()),
            Box::new(Mcg {}),
            Box::new(FtmController::new()),
            Box::new(Gpio::default()),
            Box::new(UartController::new(get_uarts())),
        ];

        let mut hints = LoaderHints::new();
        hints.insert("arch".to_string().into_boxed_str(), Box::new(Arch::Arm));

        Ok(ProcessorBundle {
            cpu,
            mmu,
            event_controller: Box::new(Nvic::default()),
            peripherals,
            loader_hints: hints,
        })
    }

    /// need to set SP from address 0 and PC from address 4
    fn init(&self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        // first try to read from address 0
        if let Ok(sp) = proc.core.mmu.read_u32_le_phys_data(0) {
            proc.core.cpu.write_register(ArmRegister::Sp, sp)?;
            if let Ok(pc) = proc.core.mmu.read_u32_le_phys_data(4) {
                proc.core.cpu.write_register(ArmRegister::Pc, pc)?;
                return Ok(());
            }
        }
        // failed to read from address 0, try 0x0800_0000
        else if let Ok(sp) = proc.core.mmu.read_u32_le_phys_data(0x0800_0000) {
            proc.core.cpu.write_register(ArmRegister::Sp, sp)?;
            if let Ok(pc) = proc.core.mmu.read_u32_le_phys_data(0x0800_0004) {
                proc.core.cpu.write_register(ArmRegister::Pc, pc)?;
                return Ok(());
            }
        }

        // neither address was readable, return error
        Err(anyhow!("failed to initialize SP and PC"))
    }
}

impl Kinetis21Builder {
    fn setup_address_space(&self, mmu: &mut Mmu) -> Result<(), UnknownError> {
        let mut regions = Vec::new();

        // Alias flash regions from
        // 0 -> 0x07ffffff to
        // 0x08000000 -> 0x08ffffff
        // as per k21 sub-family reference manual
        // note that the flash is only 1 MB so we don't
        // actually make the entire spaces valid
        let flash_memory_start = 0x0;
        let flash_alias_start = 0x0800_0000;
        let flash_size: u64 = 1024 * 1024; // 1 MB

        let flash_region = MemoryRegion::new_with_data(
            flash_memory_start,
            flash_size,
            MemoryPermissions::all(),
            vec![0xFF; flash_size as usize],
        )
        .unwrap();
        let flash_alias = flash_region.new_alias(flash_alias_start);

        // add the flash + flash alias region
        regions.push(flash_region);
        regions.push(flash_alias);

        // FlexNVM (MK21FX512VMC12) or reserved (MK21FN1M0VMC12).
        let flex_nvm_start = 0x1000_0000;
        let flex_nvm_size = 0x13FF_FFFF - flex_nvm_start + 1;
        regions.push(
            MemoryRegion::new(flex_nvm_start, flex_nvm_size, MemoryPermissions::all()).unwrap(),
        );

        // programming ram
        let flex_ram_start = 0x1400_0000;
        let flex_ram_size = 0x0400_0000;
        regions.push(
            MemoryRegion::new(flex_ram_start, flex_ram_size, MemoryPermissions::all()).unwrap(),
        );

        // programming ram alias
        let flex_ram_alias_start = 0x1800_0000;
        regions.push(
            MemoryRegion::new(
                flex_ram_alias_start,
                flex_ram_size,
                MemoryPermissions::all(),
            )
            .unwrap(),
        );

        // lower SRAM
        let sram_lower_start = 0x1c00_0000;
        let sram_lower_size = 0x0400_0000;
        regions.push(
            MemoryRegion::new(sram_lower_start, sram_lower_size, MemoryPermissions::all()).unwrap(),
        );

        // upper SRAM
        let sram_upper_start = 0x2000_0000;
        let sram_upper_size = 0x10_0000;
        regions.push(
            MemoryRegion::new(sram_upper_start, sram_upper_size, MemoryPermissions::all()).unwrap(),
        );

        // reserved 1
        let reserved_1_start = 0x2010_0000;
        let reserved_1_size = 0x01f0_0000;
        regions.push(
            MemoryRegion::new(
                reserved_1_start,
                reserved_1_size,
                MemoryPermissions::empty(),
            )
            .unwrap(),
        );

        // TODO: We don't currently implement bitband aliasing.
        // XXX: Unclear what region this is a bitband alias to.
        // alias tcmu bitband alias
        let tcmu_bitband_alias_start = 0x2200_0000;
        let tcmu_bitband_alias_size = 0x0200_0000;
        regions.push(
            MemoryRegion::new(
                tcmu_bitband_alias_start,
                tcmu_bitband_alias_size,
                MemoryPermissions::all(),
            )
            .unwrap(),
        );

        // reserved 2
        let reserved_2_start = 0x2400_0000;
        let resreved_2_size = 0x1c00_0000;
        regions.push(
            MemoryRegion::new(
                reserved_2_start,
                resreved_2_size,
                MemoryPermissions::empty(),
            )
            .unwrap(),
        );

        // aips0 bitband
        let aips0_bitband_start = 0x4000_0000;
        let aips0_bitband_size = 0x0008_0000;
        regions.push(
            MemoryRegion::new(
                aips0_bitband_start,
                aips0_bitband_size,
                MemoryPermissions::all(),
            )
            .unwrap(),
        );

        // aips1 bitband
        let aips1_bitband_start = 0x4008_0000;
        let aips1_bitband_size = 0x7_f000;
        regions.push(
            MemoryRegion::new(
                aips1_bitband_start,
                aips1_bitband_size,
                MemoryPermissions::all(),
            )
            .unwrap(),
        );

        // gpio bitband
        let gpio_bitband_start = 0x400f_f000;
        let gpio_bitband_size = 0x1000;
        regions.push(
            MemoryRegion::new(
                gpio_bitband_start,
                gpio_bitband_size,
                MemoryPermissions::all(),
            )
            .unwrap(),
        );

        // reserved 3
        let reserved_3_start = 0x4010_0000;
        let reserved_3_size = 0x1f0_0000;
        regions.push(
            MemoryRegion::new(
                reserved_3_start,
                reserved_3_size,
                MemoryPermissions::empty(),
            )
            .unwrap(),
        );

        // TODO: We don't currently implement bitband aliasing.
        // aips and gpio bitband alias
        let aips_gpio_bitband_start = 0x4200_0000;
        let aips_gpio_bitband_size = 0x0200_0000;
        regions.push(
            MemoryRegion::new(
                aips_gpio_bitband_start,
                aips_gpio_bitband_size,
                MemoryPermissions::all(),
            )
            .unwrap(),
        );

        // reserved 4
        let reserved_4_start = 0x4400_0000;
        let reserved_4_size = 0x1c00_0000;
        regions.push(
            MemoryRegion::new(
                reserved_4_start,
                reserved_4_size,
                MemoryPermissions::empty(),
            )
            .unwrap(),
        );

        // flexbus EXT memory + WB
        let flexbus_ext_wb_start = 0x6000_0000;
        let flexbus_ext_wb_size = 0x2000_0000;
        regions.push(
            MemoryRegion::new(
                flexbus_ext_wb_start,
                flexbus_ext_wb_size,
                MemoryPermissions::all(),
            )
            .unwrap(),
        );

        // flexbus EXT memory + WT
        let flexbus_ext_wt_start = 0x8000_0000;
        let flexbus_ext_wt_size = 0x2000_0000;
        regions.push(
            MemoryRegion::new(
                flexbus_ext_wt_start,
                flexbus_ext_wt_size,
                MemoryPermissions::all(),
            )
            .unwrap(),
        );

        // flexbus EXT peripheral NX
        let flexbus_ext_peripheral_start = 0xa000_0000;
        let flexbus_ext_peripheral_size = 0x4000_0000;
        regions.push(
            MemoryRegion::new(
                flexbus_ext_peripheral_start,
                flexbus_ext_peripheral_size,
                MemoryPermissions::READ | MemoryPermissions::WRITE,
            )
            .unwrap(),
        );

        // private peripherals
        let private_peripherals_start = 0xe000_0000;
        let private_peripherals_size = 0x10_0000;
        regions.push(
            MemoryRegion::new(
                private_peripherals_start,
                private_peripherals_size,
                MemoryPermissions::READ | MemoryPermissions::WRITE,
            )
            .unwrap(),
        );

        // reserved 5
        let reserved_5_start = 0xe010_0000;
        let reserved_5_size = 0x1fef_f000; // changed from 0x1ff0_0000 to make room for RFI address space, mapped in the NVIC
        regions.push(
            MemoryRegion::new(
                reserved_5_start,
                reserved_5_size,
                MemoryPermissions::empty(),
            )
            .unwrap(),
        );

        for region in regions {
            mmu.add_memory_region(region)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(dead_code)] // TODO
mod tests {
    use std::{borrow::Cow, path::Path};

    use styx_core::{executor::SingleStepExecutor, prelude::*};
    use tracing::info;

    use super::*;

    /// instructions to map in and use for the generated tests
    #[rustfmt::skip]
    const NOP_INSNS: &[u8] = &[0x00, 0x00, 0x00, 0x20, // Set SP to `0x2000_0000`
                               0x08, 0x00, 0x00, 0x00, // Set PC to `0x8` (first nop)
                               0x00, 0xf0, 0x20, 0xe3, // NOP
                               0x00, 0xf0, 0x20, 0xe3, // NOP
                               0x00, 0xf0, 0x20, 0xe3, // NOP
                               0x00, 0xf0, 0x20, 0xe3, // NOP
    ];

    fn create_default_k21_with_nop_code(input_bytes: Cow<'_, [u8]>) -> ProcessorBuilder<'_> {
        ProcessorBuilder::default()
            .with_loader(RawLoader)
            .with_builder(Kinetis21Builder::default())
            .with_input_bytes(input_bytes)
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn code_tests() {
        let path_str = resolve_test_bin("arm/kinetis_21/bin/nvic_tests/nvic_tests_debug.bin");
        let filepath = Path::new(&path_str);

        if !filepath.exists() || !filepath.is_file() {
            panic!("Test bin not found.  Expected file to exist: '{path_str}'");
        }

        styx_core::util::logging::init_logging();

        // addresses of marker functions in the binary we hook to tell if a test was passed or failed.
        const PASS_ADDR: u64 = 0xb34;
        const FAIL_ADDR: u64 = 0xb42;

        let pass = |_proc: CoreHandle| -> Result<(), UnknownError> {
            info!("test passed");
            Ok(())
        };
        let fail = |proc: CoreHandle| {
            panic!("test failed: pc=0x{:x}", proc.cpu.pc().unwrap());
        };

        let mut proc = ProcessorBuilder::default()
            .with_builder(Kinetis21Builder::default())
            .with_executor(SingleStepExecutor)
            .with_loader(RawLoader)
            .with_target_program(path_str)
            .build()
            .unwrap();

        proc.code_hook(FAIL_ADDR, FAIL_ADDR | 1, Box::new(fail))
            .unwrap();
        proc.code_hook(PASS_ADDR, PASS_ADDR | 1, Box::new(pass))
            .unwrap();

        proc.run(Forever).unwrap();
    }
}
