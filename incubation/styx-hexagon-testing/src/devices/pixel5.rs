// SPDX-License-Identifier: BSD-2-Clause

use styx_emulator::{
    errors::UnknownError,
    hooks::{CoreHandle, StyxHook},
    prelude::{Processor, WriteExt},
    processors::hexagon::hexagon::{HexagonConfigTable, HexagonProcessorConfig, QTimerConfig},
};

use super::HexagonDevice;

#[derive(Default)]
pub struct Pixel5 {}

impl HexagonDevice for Pixel5 {
    fn hooks(&self) -> Result<Vec<StyxHook>, UnknownError> {
        // Both hooks here are for an unknown peripheral (which very well could be one of the implemented ones,
        // but not sure). These hooks set values in the MMIO region of this peripheral such that the firmware
        // continues to progress.
        Ok(vec![
            StyxHook::MemoryRead(
                (0x04080028..0x0408002c).into(),
                Box::new(
                    |proc: CoreHandle, _address: u64, _size: u32, _data: &mut [u8]| {
                        proc.mmu.write_u32_le_phys_data(0x04080028, 0xfffffff0)?;

                        Ok(())
                    },
                ),
            ),
            StyxHook::MemoryRead(
                (0x04122000..0x04122004).into(),
                Box::new(
                    |proc: CoreHandle, _address: u64, _size: u32, _data: &mut [u8]| {
                        let val = proc.mmu.read_u32_le_phys_data(0x04122000)?;
                        proc.mmu.write_u32_le_phys_data(0x04122000, val + 0x100)?;

                        Ok(())
                    },
                ),
            ),
        ])
    }

    fn proc_config(&self) -> Result<HexagonProcessorConfig, UnknownError> {
        Ok(HexagonProcessorConfig {
            config_table: [
                (HexagonConfigTable::L2TCM, 0x540),
                (HexagonConfigTable::L2EcomemSize, 0x800),
                (HexagonConfigTable::L2Config, 0x57a),
                (HexagonConfigTable::Etm, 0x57a),
                (HexagonConfigTable::L2InstructionTCM, 0x560),
                (HexagonConfigTable::Clade1, 0x57d),
                (HexagonConfigTable::Clade2, 0x55b),
            ]
            .into_iter()
            .collect(),
            qtimer_config: QTimerConfig {
                irq: 2,
                ..Default::default()
            },
            ..Default::default()
        })
    }

    fn post_init(&self, proc: &mut Processor) -> Result<(), UnknownError> {
        let memory = proc.memory().data();
        memory.write(0x04122000).le().value(0x100u32)?;
        memory.write(0x4090000).le().value(0xffffffffu32)?;
        Ok(())
    }
}
