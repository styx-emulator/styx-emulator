// SPDX-License-Identifier: BSD-2-Clause
use log::log_enabled;
use std::mem::size_of;
use styx_core::prelude::*;

use super::sd_mmc_hooks;
use styx_cyclone_v_hps_sys::{generic::FromBytes, sdmmc, Sdmmc};

pub const SDMMC_BASE: u64 = Sdmmc::BASE as u64;
pub const SDMMC_STRUCT_SIZE: usize = size_of::<sdmmc::RegisterBlock>();
pub const SDMMC_REGION_SIZE: usize = 0x400;
#[allow(dead_code)]
pub const SDMMC_RESERVED_REGION_SIZE: usize = 0x1000; // 4Kb is reserved by the HW for SD/MMC

/// Right know we only support `eMMC` since thats what our hw dev case is
pub struct CycloneVSDMMC {
    pub paused: bool,
}

impl CycloneVSDMMC {
    pub fn new() -> Self {
        Self { paused: false }
    }
}

impl Peripheral for CycloneVSDMMC {
    fn reset(
        &mut self,
        _cpu: &mut dyn styx_core::prelude::CpuBackend,
        mmu: &mut styx_core::prelude::Mmu,
    ) -> Result<(), UnknownError> {
        self.paused = false;

        let mut memory_bytes = [0_u8; SDMMC_STRUCT_SIZE];
        mmu.read_data(SDMMC_BASE, &mut memory_bytes)?;

        // # Safety
        // Bytes being copied to the struct are all zeroes, which is a valid representation.
        let reg = unsafe { sdmmc::RegisterBlock::from_bytes(&memory_bytes).unwrap() };

        // # Safety
        // This unsafe block is performing hardware initialization,
        // so it should use the sys_reset/register_clear methods
        //
        // in other words "permissions have no bearing here"
        unsafe {
            // setup the default state as per the SDMMC Module man page
            reg.ctrl().sys_reset();
            reg.pwren().sys_reset();
            reg.clkdiv().sys_reset();
            reg.clksrc().sys_reset();
            reg.clkena().sys_reset();
            reg.tmout().sys_reset();
            reg.ctype().sys_reset();
            reg.blksiz().sys_reset();
            reg.bytcnt().sys_reset();
            reg.intmask().sys_reset();
            reg.cmdarg().sys_reset();
            reg.cmd().sys_reset();
            reg.resp0().sys_reset();
            reg.resp1().sys_reset();
            reg.resp2().sys_reset();
            reg.resp3().sys_reset();
            reg.mintsts().sys_reset();
            reg.rintsts().sys_reset();
            reg.status().sys_reset();
            reg.fifoth().sys_reset();
            reg.cdetect().sys_reset();
            reg.wrtprt().sys_reset();
            reg.tcbcnt().sys_reset();
            reg.tbbcnt().sys_reset();
            reg.debnce().sys_reset();
            reg.usrid().sys_reset();
            reg.verid().sys_reset();
            reg.hcon().sys_reset();
            reg.uhs_reg().sys_reset();
            reg.rst_n().sys_reset();
            reg.bmod().sys_reset();
            reg.pldmnd().sys_reset();
            reg.dbaddr().sys_reset();
            reg.idsts().sys_reset();
            reg.idinten().sys_reset();
            reg.dscaddr().sys_reset();
            reg.bufaddr().sys_reset();
            reg.cardthrctl().sys_reset();
            reg.back_end_power_r().sys_reset();
            reg.data().sys_register_clear();
        }
        // write memory to the cpu
        mmu.write_data(SDMMC_BASE, reg.as_bytes_ref())?;

        Ok(())
    }

    /// Interrupts assigned to the SDMMC controller subsystem:
    ///
    /// | number | name                            |
    /// |--------|---------------------------------|
    /// | 171    | sdmmc_IRQ                       |
    /// | 172    | sdmmc_porta_ecc_corrected_IRQ   |
    /// | 173    | sdmmc_porta_ecc_uncorrected_IRQ |
    /// | 174    | sdmmc_portb_ecc_corrected_IRQ   |
    /// | 175    | sdmmc_portb_ecc_uncorrected_IRQ |
    fn irqs(&self) -> Vec<styx_core::prelude::ExceptionNumber> {
        vec![171, 172, 173, 174, 175]
    }

    fn init(
        &mut self,
        proc: &mut styx_core::prelude::BuildingProcessor,
    ) -> Result<(), UnknownError> {
        // conditionally enable our debug hooks -- it can get verbose
        if log_enabled!(log::Level::Debug) {
            // add our read hook
            proc.core.cpu.mem_read_hook(
                SDMMC_BASE,
                SDMMC_BASE + SDMMC_REGION_SIZE as u64,
                Box::new(sd_mmc_hooks::sdmmc_region_read_debug_hook),
            )?;

            // add our write hook
            proc.core.cpu.mem_write_hook(
                SDMMC_BASE,
                SDMMC_BASE + SDMMC_REGION_SIZE as u64,
                Box::new(sd_mmc_hooks::sdmmc_region_write_debug_hook),
            )?;
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "SD MMC"
    }
}

#[cfg(test)]
mod tests {
    use styx_core::prelude::*;

    use crate::CycloneVBuilder;

    use super::*;
    use std::borrow::Cow;

    struct TestMachine {
        proc: Processor,
    }

    impl TestMachine {
        fn new() -> Self {
            // Dummy program, never run
            let program = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

            let proc = ProcessorBuilder::default()
                .with_builder(CycloneVBuilder::default())
                .with_input_bytes(Cow::Borrowed(&program))
                .build()
                .unwrap();

            Self { proc }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_initial_memory_state_correct() {
        let mut machine = TestMachine::new(); // initialize the machine

        // this is the "correct" initial state of the in-memory struct
        // for the sd/mmc controller on the cyclone v hps
        let region: Vec<u8> = {
            let mut region = vec![0; 5 * 4];
            region.extend_from_slice(&[0x40, 0xff, 0xff, 0xff]);
            region.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            region.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]);
            region.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]);
            region.extend_from_slice(&[0x00; 2 * 4]);
            region.extend_from_slice(&[0x00, 0x00, 0x00, 0x20]);
            region.extend_from_slice(&[0x00; 6 * 4]);
            region.extend_from_slice(&[0x06, 0x01, 0x00, 0x00]);
            region.extend_from_slice(&[0x00, 0x00, 0xff, 0x03]);
            region.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
            region.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
            region.extend_from_slice(&[0x00; 3 * 4]);
            region.extend_from_slice(&[0xff, 0xff, 0xff, 0x00]);
            region.extend_from_slice(&[0x97, 0x77, 0x96, 0x07]);
            region.extend_from_slice(&[0x0a, 0x24, 0x42, 0x53]);
            region.extend_from_slice(&[0x81, 0x30, 0xc4, 0x00]);
            region.extend_from_slice(&[0x00; 4]);
            region.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
            region.extend_from_slice(&[0x00; 0xf8 + 0x64 + 11 * 4]);
            region
        };

        // get memory
        let mut mem = [0_u8; SDMMC_STRUCT_SIZE];
        machine.proc.core.read_data(SDMMC_BASE, &mut mem).unwrap();

        assert_eq!(region, mem.to_vec(), "Initial memory is not correct");
    }
}
