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
//! Implementations of the MPC8xx Processor Family (PowerQUICC I)
//!
//! # Reference Manual
//! [MPC866 PowerQUICC Family Reference Manual](https://www.nxp.com/docs/en/reference-manual/MPC866UM.pdf)
//! [Family Homepage](https://www.nxp.com/products/processors-and-microcontrollers/legacy-mpu-mcus/powerquicc-processors)
//!
//! # Implementation Details
//!
//! ## Reset Configuration
//! As Chapter `11.3.1 Hard Reset` per for reference manual, the
//! default startup behavior is determined by sampling the data
//! bus @ 32bits.
//!
//! We default to:
//!
//! ```text
//! | Bit | Name | Value | Effect |
//! |-----|------|-------|--------|
//! |  0  | EARB |   0   | No external arbitration |
//! |  1  | IIP  |   1   | MSR[IP] == 0x0 (Interrupt vector table @ 0x0) |
//! |  2  | BBE  |   0   | Boot Device does not support bursting |
//! |  3  | BDIS |   0   | Memory Controller is activated and matches all addresses |
//! | 4-5 | BPS  |   00  | Port size of boot device is 32 Bits |
//! |  6  |  -   |   0   | N/A |
//! | 7-8 | ISB  |   10  | Initial IMMR[0-15] == 0xFF, and base address of internal memory is 0 |
//! | 9-10| DBGC |   00  | N/A |
//! |11-12| DBPC |   00  | N/A |
//! |13-14| EBDF |   00  | CLKOUT is GCLK2 divided by 1, Full Speed Bus |
//! | 15  | CLES |   0   | Big Endian |
//! ```
use styx_core::core::builder::BuildProcessorImplArgs;
use styx_core::cpu::arch::ppc32::variants::Mpc8xxVariants;
use styx_core::cpu::UnicornBackend;
use styx_core::errors::anyhow::anyhow;
use styx_core::memory::memory_region::MemoryRegion;
use styx_core::memory::MemoryPermissions;
use styx_core::{core::builder::ProcessorImpl, cpu::PcodeBackend, prelude::*};
use styx_mpc866m::Mpc866mController;

use self::fast_ethernet::FastEthernetController;
use self::pcmcia::Pcmcia;
use self::system_interface_unit::SystemInterfaceUnit;
use self::utopia::UtopiaBlock;

pub mod communications_processor;
pub mod fast_ethernet;
pub mod immr;
pub mod pcmcia;
pub mod peripherals;
pub mod system_interface_unit;
pub mod utopia;

/// Processor Implementation for the MPC8XX Family (PowerQUICC I).
///
/// Note that The MPC8XX line is implemented with 2 discrete
/// processors, and 3 main "units"
/// - System Interface Unit
/// - Embedded MPX8xx Processor Core
/// - 32-bit RISC Controller + Program ROM
///
/// In addition to that, there are multiple packages that
/// the processor family was shipped with, each with their
/// own configured or enabled peripherals, or with different
/// counts of enabled peripherals.
///
/// To account for this variety, the [`Mpc8xxVariants`] are
/// used on initialization to properly configure the
/// processor tree.
pub struct Mpc8xxBuilder {
    family_variant: Mpc8xxVariants,
    meta_variant: ArchVariant,
    endian: ArchEndian,
}

impl Mpc8xxBuilder {
    pub fn new(variant: impl Into<ArchVariant>, endian: ArchEndian) -> Result<Self, UnknownError> {
        let variant: ArchVariant = variant.into();
        if let Ok(mpc_variant) = TryInto::<Mpc8xxVariants>::try_into(variant.clone()) {
            Ok(Self {
                family_variant: mpc_variant,
                meta_variant: variant,
                endian,
            })
        } else {
            Err(anyhow!("invalid variant"))
        }
    }
}

impl ProcessorImpl for Mpc8xxBuilder {
    fn build(&self, args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError> {
        let mut cpu: Box<dyn CpuBackend> = match args.backend {
            Backend::Pcode => Box::new(PcodeBackend::new_engine_config(
                self.meta_variant.clone(),
                self.endian,
                &args.into(),
            )),
            Backend::Unicorn => Box::new(UnicornBackend::new_engine(
                Arch::Ppc32,
                self.meta_variant.clone(),
                self.endian,
            )),
        };

        let mut mmu = Mmu::default_region_store();

        self.setup_address_space(&mut mmu)?;

        // always start at the reset exception handler located @ 0x100
        cpu.set_pc(0x100)?;

        let cec = Box::new(Mpc866mController::new(self.family_variant));

        let peripherals: Vec<Box<dyn Peripheral>> = vec![
            Box::new(FastEthernetController),
            Box::new(Pcmcia),
            Box::new(UtopiaBlock),
            Box::new(SystemInterfaceUnit::new(self.family_variant)),
        ];

        let mut hints = LoaderHints::new();
        hints.insert("arch".to_string().into_boxed_str(), Box::new(Arch::Ppc32));
        Ok(ProcessorBundle {
            cpu,
            mmu,
            event_controller: cec,
            peripherals,
            loader_hints: hints,
        })
    }
}

impl Mpc8xxBuilder {
    fn setup_address_space(&self, mmu: &mut Mmu) -> Result<(), UnknownError> {
        let mut regions = Vec::new();

        // flash
        // 0x00 -> 0x300000;
        let flash_start = 0x0;
        let flash_size: u64 = 0x30_0000;
        let flash_region = MemoryRegion::new_with_data(
            flash_start as u64,
            flash_size,
            MemoryPermissions::all(),
            vec![0xFF; flash_size as usize],
        )
        .unwrap();

        regions.push(flash_region);

        // ram?
        // 0x00300000 -> 0x0200_0000
        regions
            .push(MemoryRegion::new(0x0030_0000, 0x01d0_0000, MemoryPermissions::all()).unwrap());

        // ram?
        // 0x03800000 -> 0x038f_ffff
        regions
            .push(MemoryRegion::new(0x0380_0000, 0x0010_0000, MemoryPermissions::all()).unwrap());

        // ram (16kb, same size as immr)
        // 0x04000000 -> 0x0410_2fff
        regions
            .push(MemoryRegion::new(0x0400_0000, 0x0010_3000, MemoryPermissions::all()).unwrap());

        // ram ?
        // 0x044e0000 -> 0x044e_00ff
        // rounded to nearest 0x1000
        regions.push(MemoryRegion::new(0x044e_0000, 0x000_1000, MemoryPermissions::all()).unwrap());

        // ram ?
        // 0x047e0000 -> 0x047e_00ff
        // rounded to nearest 0x1000
        regions
            .push(MemoryRegion::new(0x047e_0000, 0x0000_1000, MemoryPermissions::all()).unwrap());

        // IMMR
        // 0x06000000 -> 0x0610_02ff
        // rounded to nearest 0x1000
        regions
            .push(MemoryRegion::new(0x0600_0000, 0x0010_1000, MemoryPermissions::all()).unwrap());

        // top level space -- gdb wants it ???
        regions.push(
            MemoryRegion::new(
                0xff00_0000,
                0x0100_0000,
                MemoryPermissions::READ | MemoryPermissions::WRITE,
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
    #[allow(unused_macros)]
    macro_rules! mpc8xx_plugin_integration {
        // module name, enum variant
        ($name:ident, $type_name:expr_2021) => {
            mod $name {
                use super::*;

                const NOP_INSNS: &[u8] = &create_nop_contents::<0x200>();

                const fn create_nop_contents<const DIM: usize>() -> [u8; DIM] {
                    let mut array = [0x0; DIM];
                    let mut i = 0;

                    // NOP is [0x60, 0x00, 0x00, 0x00]
                    while i < DIM {
                        array[i] = 0x60;
                        i += 4;
                    }

                    array
                }

                #[allow(clippy::extra_unused_type_parameters)]
                fn build_mpc_variant(input_bytes: Cow<'_, [u8]>) -> ProcessorBuilder<'_> {
                    ProcessorBuilder::default()
                        .with_loader(RawLoader)
                        .with_builder(Mpc8xxBuilder::new($type_name, ArchEndian::BigEndian))
                        .with_input_bytes(input_bytes)
                }

                test_processor_plugin_integration!(Mpc8xxProcessor, NOP_INSNS, build_mpc_variant);
            }
        };
    }
}
