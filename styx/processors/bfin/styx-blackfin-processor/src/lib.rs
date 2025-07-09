// SPDX-License-Identifier: BSD-2-Clause
//! Blackfin processor.
//!
//! Currently has decent support for core and peripheral interrupts. Also has support for [DMA](dma),
//! [SPORT](sport), and [timers] with some features missing.
mod core_event_controller;
mod dma;
mod sport;
mod timers;

use dma::DmaController;
use dma::{DmaPeripheralMapping, DmaSources};
use sport::sport_sin_sample;
use styx_core::core::builder::{BuildProcessorImplArgs, ProcessorImpl};
use styx_core::cpu::arch::blackfin::BlackfinMetaVariants;
use styx_core::cpu::arch::blackfin::BlackfinVariants;
use styx_core::cpu::PcodeBackend;
use styx_core::memory::memory_region::MemoryRegion;
use styx_core::memory::MemoryPermissions;
use styx_core::prelude::*;

use core_event_controller::CoreEventController;
use timers::Timers;

// we do *not* support the BF535 variant, it's "special"
fn allowed_bfin_variant(v: BlackfinVariants) -> bool {
    let v = v.into();
    match v {
        ArchVariant::Blackfin(ref bfin_variant) => {
            !matches!(bfin_variant, BlackfinMetaVariants::Bf535(_))
        }
        _ => false,
    }
}

pub struct BlackfinBuilder {
    pub variant: BlackfinVariants,
}

impl Default for BlackfinBuilder {
    fn default() -> Self {
        Self {
            variant: BlackfinVariants::Bf512,
        }
    }
}

impl ProcessorImpl for BlackfinBuilder {
    fn build(&self, args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError> {
        if !allowed_bfin_variant(self.variant) {
            return Err(anyhow::anyhow!(
                "blackfin variant {} not supported",
                self.variant
            ));
        }

        let cpu = if let Backend::Pcode = args.backend {
            Box::new(PcodeBackend::new_engine_config(
                self.variant,
                ArchEndian::LittleEndian,
                &args.into(),
            ))
        } else {
            return Err(anyhow!("blackfin processor only supports pcode backend"));
        };

        let mut mmu = Mmu::default_region_store();

        self.setup_address_space(&mut mmu)?;

        // initial_registers(cpu.as_mut())?;
        let cec = Box::new(CoreEventController::default());

        let mut peripherals: Vec<Box<dyn Peripheral>> = Vec::new();
        let timers = Box::new(Timers::new(cec.get_sic()));
        peripherals.push(timers);
        // populate dma sources
        let mut mapping = DmaSources::default();

        let sin1 = args.runtime.block_on(sport_sin_sample());
        let sin2 = args.runtime.block_on(sport_sin_sample());
        mapping.set(DmaPeripheralMapping::Sport0Receive, sin1);
        mapping.set(
            DmaPeripheralMapping::Sport1ReceiveOrSpi1TransmitReceive,
            sin2,
        );
        let dma = Box::new(DmaController::new(cec.get_sic(), mapping));
        peripherals.push(dma);

        let mut hints = LoaderHints::new();
        hints.insert(
            "arch".to_string().into_boxed_str(),
            Box::new(Arch::Blackfin),
        );

        Ok(ProcessorBundle {
            cpu,
            mmu,
            event_controller: cec,
            peripherals,
            loader_hints: hints,
        })
    }
}

impl BlackfinBuilder {
    fn setup_address_space(&self, mmu: &mut Mmu) -> Result<(), UnknownError> {
        let mut regions = Vec::new();

        let sdram_start = 0;
        let sdram_size = 0x08000000;
        regions.push(MemoryRegion::new(sdram_start, sdram_size, MemoryPermissions::all()).unwrap());

        let async_bank_0_start = 0x20000000;
        let async_bank_0_size = 0x100000;
        regions.push(
            MemoryRegion::new(
                async_bank_0_start,
                async_bank_0_size,
                MemoryPermissions::all(),
            )
            .unwrap(),
        );

        let async_bank_1_start = 0x20100000;
        let async_bank_1_size = 0x100000;
        regions.push(
            MemoryRegion::new(
                async_bank_1_start,
                async_bank_1_size,
                MemoryPermissions::all(),
            )
            .unwrap(),
        );

        let async_bank_2_start = 0x20200000;
        let async_bank_2_size = 0x100000;
        regions.push(
            MemoryRegion::new(
                async_bank_2_start,
                async_bank_2_size,
                MemoryPermissions::all(),
            )
            .unwrap(),
        );

        let async_bank_3_start = 0x20300000;
        let async_bank_3_size = 0x100000;
        regions.push(
            MemoryRegion::new(
                async_bank_3_start,
                async_bank_3_size,
                MemoryPermissions::all(),
            )
            .unwrap(),
        );

        let bootrom_start = 0xef000000;
        let bootrom_size = 0x8000;
        regions.push(
            MemoryRegion::new(
                bootrom_start,
                bootrom_size,
                MemoryPermissions::READ | MemoryPermissions::EXEC,
            )
            .unwrap(),
        );

        let data_bank_a_sram_start = 0xff800000;
        let data_bank_a_sram_size = 0x4000;
        regions.push(
            MemoryRegion::new(
                data_bank_a_sram_start,
                data_bank_a_sram_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let data_bank_a_sram_cache_start = 0xff804000;
        let data_bank_a_sram_cache_size = 0x4000;
        regions.push(
            MemoryRegion::new(
                data_bank_a_sram_cache_start,
                data_bank_a_sram_cache_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let data_bank_b_sram_start = 0xff900000;
        let data_bank_b_sram_size = 0x4000;
        regions.push(
            MemoryRegion::new(
                data_bank_b_sram_start,
                data_bank_b_sram_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let data_bank_b_sram_cache_start = 0xff904000;
        let data_bank_b_sram_cache_size = 0x4000;
        regions.push(
            MemoryRegion::new(
                data_bank_b_sram_cache_start,
                data_bank_b_sram_cache_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let instruction_bank_a_sram_start = 0xffa00000;
        let instruction_bank_a_sram_size = 0x4000;
        regions.push(
            MemoryRegion::new(
                instruction_bank_a_sram_start,
                instruction_bank_a_sram_size,
                MemoryPermissions::all(),
            )
            .unwrap(),
        );

        let instruction_bank_b_sram_start = 0xffa04000;
        let instruction_bank_b_sram_size = 0x4000;
        regions.push(
            MemoryRegion::new(
                instruction_bank_b_sram_start,
                instruction_bank_b_sram_size,
                MemoryPermissions::all(),
            )
            .unwrap(),
        );

        let instruction_bank_c_sram_start = 0xffa10000;
        let instruction_bank_c_sram_size = 0x4000;
        regions.push(
            MemoryRegion::new(
                instruction_bank_c_sram_start,
                instruction_bank_c_sram_size,
                MemoryPermissions::all(),
            )
            .unwrap(),
        );

        let scratchpad_sram_start = 0xffb00000;
        let scratchpad_sram_size = 0x1000;
        regions.push(
            MemoryRegion::new(
                scratchpad_sram_start,
                scratchpad_sram_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let sys_mmr_pll_start = 0xffc00000;
        let sys_mmr_pll_size = 0x0100;
        regions.push(
            MemoryRegion::new(sys_mmr_pll_start, sys_mmr_pll_size, MemoryPermissions::RW).unwrap(),
        );

        let sys_mmr_sic_start = 0xffc00100;
        let sys_mmr_sic_size = 0x0100;
        regions.push(
            MemoryRegion::new(sys_mmr_sic_start, sys_mmr_sic_size, MemoryPermissions::RW).unwrap(),
        );

        let sys_mmr_watchdog_start = 0xffc00200;
        let sys_mmr_watchdog_size = 0x0100;
        regions.push(
            MemoryRegion::new(
                sys_mmr_watchdog_start,
                sys_mmr_watchdog_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let sys_mmr_rtc_start = 0xffc00300;
        let sys_mmr_rtc_size = 0x0100;
        regions.push(
            MemoryRegion::new(sys_mmr_rtc_start, sys_mmr_rtc_size, MemoryPermissions::RW).unwrap(),
        );

        let sys_mmr_uart0_start = 0xffc00400;
        let sys_mmr_uart0_size = 0x0100;
        regions.push(
            MemoryRegion::new(
                sys_mmr_uart0_start,
                sys_mmr_uart0_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let sys_mmr_uart1_start = 0xffc02000;
        let sys_mmr_uart1_size = 0x0100;
        regions.push(
            MemoryRegion::new(
                sys_mmr_uart1_start,
                sys_mmr_uart1_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let sys_mmr_spi0_start = 0xffc00500;
        let sys_mmr_spi0_size = 0x0100;
        regions.push(
            MemoryRegion::new(sys_mmr_spi0_start, sys_mmr_spi0_size, MemoryPermissions::RW)
                .unwrap(),
        );

        let sys_mmr_timer_start = 0xffc00600;
        let sys_mmr_timer_size = 0x0100;
        regions.push(
            MemoryRegion::new(
                sys_mmr_timer_start,
                sys_mmr_timer_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let sys_mmr_portf_start = 0xffc00700;
        let sys_mmr_portf_size = 0x0100;
        regions.push(
            MemoryRegion::new(
                sys_mmr_portf_start,
                sys_mmr_portf_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let sys_mmr_portg_start = 0xffc01500;
        let sys_mmr_portg_size = 0x0100;
        regions.push(
            MemoryRegion::new(
                sys_mmr_portg_start,
                sys_mmr_portg_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let sys_mmr_porth_start = 0xffc01700;
        let sys_mmr_porth_size = 0x0100;
        regions.push(
            MemoryRegion::new(
                sys_mmr_porth_start,
                sys_mmr_porth_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let sys_mmr_port_start = 0xffc03200;
        let sys_mmr_port_size = 0x0100;
        regions.push(
            MemoryRegion::new(sys_mmr_port_start, sys_mmr_port_size, MemoryPermissions::RW)
                .unwrap(),
        );

        let sys_mmr_sport0_start = 0xffc00800;
        let sys_mmr_sport0_size = 0x0100;
        regions.push(
            MemoryRegion::new(
                sys_mmr_sport0_start,
                sys_mmr_sport0_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let sys_mmr_sport1_start = 0xffc00900;
        let sys_mmr_sport1_size = 0x0100;
        regions.push(
            MemoryRegion::new(
                sys_mmr_sport1_start,
                sys_mmr_sport1_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let sys_mmr_ebiu_start = 0xffc00a00;
        let sys_mmr_ebiu_size = 0x0100;
        regions.push(
            MemoryRegion::new(sys_mmr_ebiu_start, sys_mmr_ebiu_size, MemoryPermissions::RW)
                .unwrap(),
        );

        let sys_mmr_dma_start = 0xffc00b00;
        let sys_mmr_dma_size = 0x0500;
        regions.push(
            MemoryRegion::new(sys_mmr_dma_start, sys_mmr_dma_size, MemoryPermissions::RW).unwrap(),
        );

        let sys_mmr_ppi_start = 0xffc01000;
        let sys_mmr_ppi_size = 0x0100;
        regions.push(
            MemoryRegion::new(sys_mmr_ppi_start, sys_mmr_ppi_size, MemoryPermissions::RW).unwrap(),
        );

        let sys_mmr_twi_start = 0xffc01400;
        let sys_mmr_twi_size = 0x0100;
        regions.push(
            MemoryRegion::new(sys_mmr_twi_start, sys_mmr_twi_size, MemoryPermissions::RW).unwrap(),
        );

        let sys_mmr_hmdma_start = 0xffc03300;
        let sys_mmr_hmdma_size = 0x0100;
        regions.push(
            MemoryRegion::new(
                sys_mmr_hmdma_start,
                sys_mmr_hmdma_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let sys_mmr_spi1_start = 0xffc03400;
        let sys_mmr_spi1_size = 0x0100;
        regions.push(
            MemoryRegion::new(sys_mmr_spi1_start, sys_mmr_spi1_size, MemoryPermissions::RW)
                .unwrap(),
        );

        let sys_mmr_counter_start = 0xffc03500;
        let sys_mmr_counter_size = 0x0100;
        regions.push(
            MemoryRegion::new(
                sys_mmr_counter_start,
                sys_mmr_counter_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let sys_mmr_security_start = 0xffc03600;
        let sys_mmr_security_size = 0x0090;
        regions.push(
            MemoryRegion::new(
                sys_mmr_security_start,
                sys_mmr_security_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let sys_mmr_pwm_start = 0xffc03700;
        let sys_mmr_pwm_size = 0x0100;
        regions.push(
            MemoryRegion::new(sys_mmr_pwm_start, sys_mmr_pwm_size, MemoryPermissions::RW).unwrap(),
        );

        let sys_mmr_bf512_norsi_start = 0xffc03800;
        let sys_mmr_bf512_norsi_size = 0x0500;
        regions.push(
            MemoryRegion::new(
                sys_mmr_bf512_norsi_start,
                sys_mmr_bf512_norsi_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let mmr_l1_data_memory_controller_start = 0xffe00000;
        let mmr_l1_data_memory_controller_size = 0x0408;
        regions.push(
            MemoryRegion::new(
                mmr_l1_data_memory_controller_start,
                mmr_l1_data_memory_controller_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let mmr_l1_inst_memory_controller_start = 0xffe01000;
        let mmr_l1_inst_memory_controller_size = 0x0408;
        regions.push(
            MemoryRegion::new(
                mmr_l1_inst_memory_controller_start,
                mmr_l1_inst_memory_controller_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let mmr_l1_interrupt_controller_start = 0xffe02000;
        let mmr_l1_interrupt_controller_size = 0x0114;
        regions.push(
            MemoryRegion::new(
                mmr_l1_interrupt_controller_start,
                mmr_l1_interrupt_controller_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let mmr_core_timer_start = 0xffe03000;
        // changed from 0x10 to accommodate out of bounds reads/writes due to unicorn backend
        // compatibility (need to read/write 8 bytes for hooks)
        let mmr_core_timer_size = 0x0020;
        regions.push(
            MemoryRegion::new(
                mmr_core_timer_start,
                mmr_core_timer_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let mmr_debug_start = 0xffe05000;
        let mmr_debug_size = 0x0004;
        regions.push(
            MemoryRegion::new(mmr_debug_start, mmr_debug_size, MemoryPermissions::RW).unwrap(),
        );

        let mmr_trace_unit_start = 0xffe06000;
        let mmr_trace_unit_size = 0x0104;
        regions.push(
            MemoryRegion::new(
                mmr_trace_unit_start,
                mmr_trace_unit_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let mmr_watchpoint_start = 0xffe07000;
        let mmr_watchpoint_size = 0x0204;
        regions.push(
            MemoryRegion::new(
                mmr_watchpoint_start,
                mmr_watchpoint_size,
                MemoryPermissions::RW,
            )
            .unwrap(),
        );

        let mmr_performance_monitor_start = 0xffe08000;
        let mmr_performance_monitor_size = 0x0108;
        regions.push(
            MemoryRegion::new(
                mmr_performance_monitor_start,
                mmr_performance_monitor_size,
                MemoryPermissions::RW,
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
    use std::borrow::Cow;

    use styx_core::executor::DefaultExecutor;
    use styx_core::prelude::*;

    use styx_core::cpu::arch::blackfin::BlackfinVariants;

    use super::*;

    /// meaningless data
    const NOP_INSNS: &[u8] = &[
        0x00, 0x00, 0x00, 0x20, // Set SP to `0x2000_0000`
        0x08, 0x00, 0x00, 0x00, // Set PC to `0x8` (first nop)
        0x00, 0xf0, 0x20, 0xe3, // NOP
        0x00, 0xf0, 0x20, 0xe3, // NOP
        0x00, 0xf0, 0x20, 0xe3, // NOP
        0x00, 0xf0, 0x20, 0xe3, // NOP
    ];

    fn create_default_with_nop_code(input_bytes: Cow<'_, [u8]>) -> ProcessorBuilder<'_> {
        ProcessorBuilder::default()
            .with_loader(RawLoader)
            .with_executor(DefaultExecutor)
            .with_input_bytes(input_bytes)
    }

    #[test]
    fn create_processor() {
        ProcessorBuilder::default()
            .with_builder(BlackfinBuilder {
                variant: BlackfinVariants::Bf512,
            })
            .build()
            .unwrap();
    }
}
