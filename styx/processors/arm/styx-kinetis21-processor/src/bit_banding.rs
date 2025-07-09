// SPDX-License-Identifier: BSD-2-Clause
//! A bit-band region maps each word in a bit-band alias region to a single bit in the bit-band region.
//!
//! The public API is simple. Just put this code in the `initialize_peripherals` of your CPU.
//!
//! ```ignore
//! BitBands::<Bit32>::default()
//!     .add_band(
//!         Address::new(0x2000_0000)..Address::new(0x2010_0000),
//!         Address::new(0x2200_0000),
//!     )
//!     .register_hooks(&self.cpu)?;
//! ```
//!
//! You can add as many bands to the BitBands as needed, all bands will have callbacks installed.
//!
//! ## Implementation
//!
//! For this implementation there is one write and one read callback on the alias region that are needed to
//! uphold the invariant. The band region is used as the source of truth and reads/writes to that region are
//! untouched (no callbacks). This was chosen because most memory operations will be done in the band region
//! so reducing overhead there is key to performance.
//!
//! ### On Alias Write
//!
//! On a write to the alias region, the band region is updated (read, modify bit, write).
//!
//! ### On Alias Read
//!
//! On an alias read, the band region is read and the alias word's lsb is set accordingly.
//!
use std::ops::Range;
use styx_core::hooks::{MemoryReadHook, MemoryWriteHook};
use styx_core::prelude::*;
use tracing::{debug, info};

/// Public API to add bit-bands to CPUs
///
/// A bit-band region maps each word in a bit-band alias region to a single bit in the bit-band region.
/// Currently the focus is to implement bit-banding for the Kinetis21/Cortex-M3 CPU but this could be
/// modified to conform to other CPUs and architectures.
///
/// The guiding literature can be found [here](https://developer.arm.com/documentation/dui0552/a/the-cortex-m3-processor/memory-model/optional-bit-banding).
///

#[derive(Default)]
pub struct BitBands {
    regions: Vec<BitBand>,
}

impl BitBands {
    /// Add a single band (band region and alias region).
    ///
    /// Note that at this point bit-bands are not installed, call register_hooks()
    /// to enable them during execution.
    pub fn add_band(mut self, band_region: Range<u64>, alias_base: u64) -> Self {
        debug!(
            "Creating a band at 0x{:X}, alias at 0x{:X}",
            band_region.start, alias_base
        );

        self.regions.push(BitBand::new(band_region, alias_base));

        self
    }

    /// "Commit" bands to CPU by registering hooks.
    pub fn register_hooks(self, emu: &mut dyn CpuBackend) -> Result<(), UnknownError> {
        info!("Bit band hooks registered.",);

        for region in self.regions.into_iter() {
            emu.mem_read_hook(
                region.alias_region.start,
                region.alias_region.end,
                Box::new(region.clone()),
            )
            .unwrap();
            emu.mem_write_hook(
                region.alias_region.start,
                region.alias_region.end,
                Box::new(region),
            )
            .unwrap();
        }

        Ok(())
    }
}

/// Single bit-band mapping an alias region to a bit-band region
#[derive(Clone)]
struct BitBand {
    band_region: Range<u64>,
    alias_region: Range<u64>,
}

impl BitBand {
    fn new(band_region: Range<u64>, alias_base: u64) -> Self {
        let band_region_length = band_region.end - band_region.start;

        let alias_end = alias_base + band_region_length * 32;
        let alias_region = alias_base..alias_end;

        Self {
            band_region,
            alias_region,
        }
    }

    /// Converts an address in the alias region to an address and bit number in the bit-band region.
    fn alias_to_region_offset(&self, alias_address: u64) -> (u64, u8) {
        // address offset into the alias region
        let alias_offset = alias_address - self.alias_region.start;

        // byte offset into the bit band region
        let byte_offset = alias_offset / 32;

        // bit number
        let bit_offset = (alias_offset / 4) % 32;

        (
            byte_offset + self.band_region.start,
            bit_offset.try_into().unwrap(),
        )
    }
}

impl MemoryReadHook for BitBand {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        data: &mut [u8],
    ) -> Result<(), UnknownError> {
        debug!(
            "Bit-band read triggered at 0x{:X} (size={}, value={:?}).",
            address, size, data
        );
        // convert alias region address to bit-band address
        let (bit_band_word_offset, bit_band_bit_number) = self.alias_to_region_offset(address);

        // read word from bit band region and then shift to put bit in lsb
        let bit_band_word =
            (proc.mmu.read_u8_le_phys_data(bit_band_word_offset)? >> bit_band_bit_number) & 0x1;

        data.copy_from_slice(&[bit_band_word, 0, 0, 0]);

        Ok(())
    }
}

impl MemoryWriteHook for BitBand {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        debug!(
            "Bit-band write triggered at 0x{:X} (size={}, value={:?}).",
            address, size, data
        );

        // the value being written to the bit band alias
        let val = data[0] & 0x1;

        // convert alias region address to bit-band address
        let (bit_band_word_offset, bit_band_bit_number) = self.alias_to_region_offset(address);

        // read, then clear or set bit according to value written
        let bit_band_word = proc.mmu.read_u8_le_phys_data(bit_band_word_offset)?;
        let modified_bit_band_word = if val == 0 {
            bit_band_word & !(1 << bit_band_bit_number)
        } else {
            bit_band_word | (1 << bit_band_bit_number)
        };
        // write back to memory
        proc.mmu
            .write_u8_le_phys_data(bit_band_word_offset, modified_bit_band_word)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use keystone_engine::{Arch, Keystone, Mode};

    use crate::Kinetis21Builder;
    use styx_core::cpu::arch::arm::*;
    use styx_core::prelude::*;

    struct TestMachine {
        proc: Processor,
        instruction_count: u64,
    }

    impl TestMachine {
        /// Create a new machine to run given arm instructions.
        fn new(instr: String) -> Self {
            let mut proc = ProcessorBuilder::default()
                .with_builder(Kinetis21Builder::default())
                .build()
                .unwrap();

            // Assemble instructions
            // Processor default to thumb so we use that
            let ks = Keystone::new(Arch::ARM, Mode::THUMB)
                .expect("Could not initialize Keystone engine");
            let asm = ks.asm(instr, 0).expect("Could not assemble");
            let code = asm.bytes;
            let instruction_count = asm.stat_count.into();

            // Write generated instructions to memory
            proc.core.mmu.write_code(0x4000, &code).unwrap();
            // Start thumb execution at our instructions
            proc.core
                .cpu
                .write_register(ArmRegister::Pc, 0x4001u32)
                .unwrap();

            TestMachine {
                proc,
                instruction_count,
            }
        }

        fn run(&mut self) {
            let exit_report = self.proc.run(self.instruction_count).unwrap();

            assert_eq!(
                EmulationReport::new(
                    TargetExitReason::InstructionCountComplete,
                    InstructionReport::Exact(self.instruction_count)
                ),
                exit_report
            );
        }

        /// Read a word of memory
        fn read_memory(&mut self, addr: u64) -> u32 {
            let mut buf: [u8; 4] = [0; 4];
            self.proc.core.mmu.read_data(addr, &mut buf).unwrap();
            u32::from_le_bytes(buf)
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_alias_write() {
        // Tests writing to the alias region
        // Change is reflected in the band region
        let instr = "str r1, [r0]; ldr r1, [r0]; ldr r2, [r3]".to_owned();
        let mut machine = TestMachine::new(instr);

        machine
            .proc
            .core
            .cpu
            .write_register(ArmRegister::R0, 0x2202_0000u32)
            .unwrap();

        machine
            .proc
            .core
            .cpu
            .write_register(ArmRegister::R1, 0xFFFFFFFFu32)
            .unwrap();

        machine
            .proc
            .core
            .cpu
            .write_register(ArmRegister::R3, 0x2000_1000u32)
            .unwrap();

        let value = machine.read_memory(0x2202_0000);
        assert_eq!(value, 0);

        machine.run();

        let value = machine
            .proc
            .core
            .cpu
            .read_register::<u32>(ArmRegister::R2)
            .unwrap();
        assert_eq!(value, 1);

        let value = machine
            .proc
            .core
            .cpu
            .read_register::<u32>(ArmRegister::R1)
            .unwrap();
        assert_eq!(value, 1);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_alias_read() {
        // Tests that data in band region is reflected in alias reads
        let instr =
            "str r1, [r0]; ldr r5, [r4]; ldr r7, [r6]; ldr r9, [r8]; ldr r11, [r10]".to_owned();
        let mut machine = TestMachine::new(instr);

        machine
            .proc
            .core
            .cpu
            .write_register(ArmRegister::R0, 0x2000_1000u32)
            .unwrap();

        machine
            .proc
            .core
            .cpu
            .write_register(ArmRegister::R1, 0b1011u32)
            .unwrap();

        machine
            .proc
            .core
            .cpu
            .write_register(ArmRegister::R4, 0x2202_0000u32)
            .unwrap();
        machine
            .proc
            .core
            .cpu
            .write_register(ArmRegister::R6, 0x2202_0004u32)
            .unwrap();
        machine
            .proc
            .core
            .cpu
            .write_register(ArmRegister::R8, 0x2202_0008u32)
            .unwrap();
        machine
            .proc
            .core
            .cpu
            .write_register(ArmRegister::R10, 0x2202_000Cu32)
            .unwrap();

        machine.run();

        let value = machine
            .proc
            .core
            .cpu
            .read_register::<u32>(ArmRegister::R5)
            .unwrap();
        assert_eq!(value, 1);
        let value = machine
            .proc
            .core
            .cpu
            .read_register::<u32>(ArmRegister::R7)
            .unwrap();
        assert_eq!(value, 1);
        let value = machine
            .proc
            .core
            .cpu
            .read_register::<u32>(ArmRegister::R9)
            .unwrap();
        assert_eq!(value, 0);
        let value = machine
            .proc
            .core
            .cpu
            .read_register::<u32>(ArmRegister::R11)
            .unwrap();
        assert_eq!(value, 1);
    }
}
