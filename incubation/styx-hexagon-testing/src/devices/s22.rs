// SPDX-License-Identifier: BSD-2-Clause

use styx_emulator::{
    cpu::{arch::hexagon::HexagonRegister, CpuBackendExt},
    errors::UnknownError,
    hooks::{CoreHandle, StyxHook},
    prelude::{
        log::{info, trace},
        Processor,
    },
    processors::hexagon::hexagon::{HexagonConfigTable, HexagonProcessorConfig, QTimerConfig},
};

use super::HexagonDevice;

#[derive(Default)]
pub struct S22 {}

impl HexagonDevice for S22 {
    fn proc_config(&self) -> Result<HexagonProcessorConfig, UnknownError> {
        info!("S22 processor config");

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
                pcycles_per_packet: 32000,
                ..Default::default()
            },
            ..Default::default()
        })
    }

    fn hooks(&self) -> Result<Vec<StyxHook>, UnknownError> {
        Ok(vec![
            // This instruction takes far too long, so we must fixing.
            /*
            bc499670  00674014   { p0 = cmp.eq(r0,r7); if (!p0.new) jump:t 0xbc499670;
            bc499674  004400b0     r0 = add(r0,#32);
            bc499678  00c0c0a0     dczeroa(r0); }
            */
            StyxHook::CodeVirtual(
                0xbc499670u64.into(),
                Box::new(|proc: CoreHandle| {
                    trace!("playing with pc for long insn");
                    // update r0 to equal r7, since this
                    // packet breaks its loop after r7 is equal to r0
                    let r7 = proc.cpu.read_register::<u32>(HexagonRegister::R7).unwrap();
                    {
                        let this = &mut *proc.cpu;
                        let reg = HexagonRegister::R0;
                        let reg = reg.into();
                        this.write_register_raw(reg, r7.into())
                    }
                    .unwrap();

                    proc.cpu
                        .write_register(HexagonRegister::Pc, 0xbc49967cu32)
                        .unwrap();
                    Ok(())
                }),
            ),
            // Trying to figure out the mystery peripheral
            // is it UART, etc. ?
            StyxHook::MemoryRead(
                (0x10c2000..0x10c4000).into(),
                Box::new(
                    |proc: CoreHandle, address: u64, size: u32, data: &mut [u8]| {
                        info!(
                            "READ mystery periph {:x} size {} data {:x?} at pc {:x?}",
                            address,
                            size,
                            data,
                            proc.cpu.pc()
                        );

                        Ok(())
                    },
                ),
            ),
            StyxHook::MemoryWrite(
                (0x10c2000..0x10c4000).into(),
                Box::new(|proc: CoreHandle, address: u64, size: u32, data: &[u8]| {
                    info!(
                        "WRITE mystery periph {:x} size {} data {:x?} at pc {:x?}",
                        address,
                        size,
                        data,
                        proc.cpu.pc()
                    );

                    Ok(())
                }),
            ),
            // quick clade2 test
            StyxHook::MemoryRead(
                (0x120000000..0x140000000).into(),
                Box::new(
                    |_proc: CoreHandle, _address: u64, _size: u32, _data: &mut [u8]| {
                        /*panic!(
                            "clade2 read addr {:x} size {} data {:x?} pc {:x?}",
                            address,
                            size,
                            data,
                            proc.cpu.pc()
                        );*/

                        Ok(())
                    },
                ),
            ),
        ])
    }

    fn post_init(&self, proc: &mut Processor) -> Result<(), UnknownError> {
        // Mystery peripheral
        proc.core.mmu.write_u32_le_phys_data(0x10c2004, 1).unwrap();
        proc.core.mmu.write_u32_le_phys_data(0x10c2000, 1).unwrap();

        Ok(())
    }
}
