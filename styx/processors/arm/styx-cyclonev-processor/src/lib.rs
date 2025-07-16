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
//! Cyclone V Hard Processor System (HPS)
//!
//! The Cyclone V HPS contains a Multiprocessor Unit (MPU) subsystem, that consists of:
//!   - One or two Cortex A9 MPCore processors
//!   - L2 Cache
//!   - Accelerator Coherency Port (ACP) ID Mapper
//!   - Debugging modules
//!
//!```text
//!
//!             MPU Subsystem Address Map
//!      ┌──────────────────────────────────────┐ ────── 0xFFFF_FFFF
//!      │                                      │
//!      │        HPS Peripherals (64 MB)       │
//!      │                                      │
//!      ├──────────────────────────────────────┤ ────── 0xFC00_0000
//!      │                                      │
//!      │            HPS-to-FPGA               │
//!      │                                      │
//!      │       (FPGA-Based Peripherals)       │
//!      │                                      │
//!      │                                      │
//!      ├ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┤ <───── L2 Cache Filtering
//!      │                                      │
//!      │                                      │
//!      │                                      │
//!      │                                      │
//!      │                                      │
//!      │                                      │
//!      │                                      │
//!      │                                      │
//!      │                                      │
//!      │                SDRAM                 │
//!      │                                      │
//!      │                                      │
//!      │                                      │
//!      │                                      │
//!      │                                      │
//!      │                                      │
//!      │                                      │
//!      │                                      │
//!      │                                      │
//!      │                                      │
//!      ├──────────────────────────────────────┤ ────── 0x0010_0000 (1 MB)
//!      │             Boot Region              │
//!      └──────────────────────────────────────┘ ────── 0
//!
//!```
//!
//! SDRAM Region: Starts at 0x0010_000, but the end of the region is determined by the L2 Cache
//! Filter. The L2 Cache Filter defines a start and end address; any access within this range is
//! routed to the SDRAM. Anything outside of the range is routed to System Interconnect.
//!
//! Boot Region: During boot, the Boot Region will address the 64 KB Boot ROM. After the system
//! boots, the Boot Region can be remapped to address:
//!   - The bottom 1 MB of the SDRAM region
//!   - The 64 KB on-chip RAM
//!
use clock_manager::ClockManager;
use sd_mmc::CycloneVSDMMC;
use styx_core::arch::arm::CoProcessorValue;
use styx_core::arch_utils::arm::armv7::reset_cpsr;
use styx_core::core::builder::{BuildProcessorImplArgs, ProcessorImpl};
use styx_core::cpu::arch::arm::{arm_coproc_registers, ArmVariants};
use styx_core::cpu::{PcodeBackend, UnicornBackend};
use styx_core::memory::memory_region::MemoryRegion;
use styx_core::prelude::*;
use styx_gic::Gic;
use styx_peripherals::uart::UartController;
use tracing::{debug, trace};

mod altera_hps_sys;
mod sd_mmc;
mod sd_mmc_hooks;

mod clock_manager;
mod uart;

// this import is only used when building documentation. When the
// rust issue https://github.com/rust-lang/rust/issues/32104 is resolved
// then we can drop this crate
#[allow(unused_imports)]
use embed_doc_image::embed_doc_image;
use uart::get_uarts;

// helper tuple typedef for human-readable const address map
struct RegionInfo(
    &'static str,      // name of region
    u64,               // base address of region
    u64,               // size of region
    MemoryPermissions, // permissions for region
    Option<u8>,        // initialization of region
    Option<u64>,       // alias offset
);

impl std::fmt::Display for RegionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let init = match self.4 {
            Some(val) => format!("{val:#x}"),
            None => "-".into(),
        };

        let alias_base = match self.5 {
            Some(base) => format!("A({base:#010x})"),
            None => "-".into(),
        };

        write!(
            f,
            "Memory Region: {:20} {:#010x} {:12} {} {:5} {:13}",
            self.0, self.1, self.2, self.3, init, alias_base
        )
    }
}

const MB: u64 = 1024 * 1024;
const GB: u64 = 1024 * MB;
const KB: u64 = 1024;
const RWX: MemoryPermissions = MemoryPermissions::all();
const RW: MemoryPermissions = MemoryPermissions::RW;

/// Address map for the Cyclone V HPS. The whole address space is 4GB in size.
/// Cyclone V HPS TRM: HPS Peripheral Region Address Map - Table 2-3 (starting on page 2-17)
/// describes the sections from STM to the end of the array.
#[allow(clippy::identity_op)]
#[rustfmt::skip]
const ADDRESS_MAP: [RegionInfo; 53] = [
    // The Boot Region takes up the initial 1MB of the address space. Note, once the system is
    // running, this address range can be remapped to either the bottom 1MB of the SDRAM region or
    // to the on-chip RAM (OCRAM).
    RegionInfo("BOOT",	        0x0000_0000,	1*MB,               RWX, None, None),

    // The end of the SDRAM address range depends on how the L2 Cache Filtering is set up. For the
    // purpose of this allocation, we are calling the entire region SDRAM. The HPS Peripherals
    // begin 64MB from the end of the address space, and we are starting 1MB into the address
    // space..
    RegionInfo("SDRAM",	        0x0010_0000,	4*GB - 64*MB - MB,  RWX, None, None),

    // HPS Peripherals. Makes up the final 64MB of the address space.
    RegionInfo("STM",	            0xFC00_0000,	48*MB,              RW,  None, None),
    RegionInfo("DAP",	            0xFF00_0000, 	2*MB,               RW,  None, None),
    RegionInfo("LWFPGASLAVES",	0xFF20_0000, 	2*MB,               RW,  None, None),
    RegionInfo("LWHPS2FPGAREGS",	0xFF40_0000, 	1*MB,               RW,  None, None),
    RegionInfo("HPS2FPGAREGS",	0xFF50_0000, 	1*MB,               RW,  None, None),
    RegionInfo("FPGA2HPSREGS",	0xFF60_0000, 	1*MB,               RW,  None, None),
    RegionInfo("EMAC0",	        0xFF70_0000, 	8*KB,               RW,  None, None),
    RegionInfo("EMAC1",	        0xFF70_2000, 	8*KB,               RW,  None, None),
    RegionInfo("SDMMC",	        0xFF70_4000, 	4*KB,               RW,  None, None),
    RegionInfo("QSPIREGS",	    0xFF70_5000, 	4*KB,               RW,  None, None),
    RegionInfo("FPGAMGRREGS",	    0xFF70_6000, 	4*KB,               RW,  None, None),
    RegionInfo("ACPIDMAP",	    0xFF70_7000, 	4*KB,               RW,  None, None),
    RegionInfo("GPIO0",	        0xFF70_8000, 	4*KB,               RW,  None, None),
    RegionInfo("GPIO1",	        0xFF70_9000, 	4*KB,               RW,  None, None),
    RegionInfo("GPIO2",	        0xFF70_A000, 	4*KB,               RW,  None, None),
    RegionInfo("L3REGS",	        0xFF80_0000, 	1*MB,               RW,  None, None),
    RegionInfo("NANDDATA",	    0xFF90_0000, 	64*KB,              RW,  None, None),
    RegionInfo("QSPIDATA",	    0xFFA0_0000, 	1*MB,               RW,  None, None),
    RegionInfo("USB0",	        0xFFB0_0000, 	256*KB,             RW,  None, None),
    RegionInfo("USB1",	        0xFFB4_0000, 	256*KB,             RW,  None, None),
    RegionInfo("NANDREGS",	    0xFFB8_0000, 	64*KB,              RW,  None, None),
    RegionInfo("FPGAMGRDATA",	    0xFFB9_0000, 	4*KB,               RW,  None, None),
    RegionInfo("CAN0",	        0xFFC0_0000, 	4*KB,               RW,  None, None),
    RegionInfo("CAN1",	        0xFFC0_1000, 	4*KB,               RW,  None, None),
    RegionInfo("UART0",	        0xFFC0_2000, 	4*KB,               RW,  None, None),
    RegionInfo("UART1",	        0xFFC0_3000, 	4*KB,               RW,  None, None),
    RegionInfo("I2C0",	        0xFFC0_4000, 	4*KB,               RW,  None, None),
    RegionInfo("I2C1",	        0xFFC0_5000, 	4*KB,               RW,  None, None),
    RegionInfo("I2C2",	        0xFFC0_6000, 	4*KB,               RW,  None, None),
    RegionInfo("I2C3",	        0xFFC0_7000, 	4*KB,               RW,  None, None),
    RegionInfo("SPTIMER0",	    0xFFC0_8000, 	4*KB,               RW,  None, None),
    RegionInfo("SPTIMER1",	    0xFFC0_9000, 	4*KB,               RW,  None, None),
    RegionInfo("SDRREGS",	        0xFFC2_0000, 	128*KB,             RW,  None, None),
    RegionInfo("OSC1TIMER0",	    0xFFD0_0000, 	4*KB,               RW,  None, None),
    RegionInfo("OSC1TIMER1",	    0xFFD0_1000, 	4*KB,               RW,  None, None),
    RegionInfo("L4WD0",	        0xFFD0_2000, 	4*KB,               RW,  None, None),
    RegionInfo("L4WD1",	        0xFFD0_3000, 	4*KB,               RW,  None, None),
    RegionInfo("CLKMGR",	        0xFFD0_4000, 	4*KB,               RW,  None, None),
    RegionInfo("RSTMGR",	        0xFFD0_5000, 	4*KB,               RW,  None, None),
    RegionInfo("SYSMGR",	        0xFFD0_8000, 	16*KB,              RW,  None, None),
    RegionInfo("DMANONSECURE",	0xFFE0_0000, 	4*KB,               RW,  None, None),
    RegionInfo("DMASECURE",	    0xFFE0_1000, 	4*KB,               RW,  None, None),
    RegionInfo("SPIS0",	        0xFFE0_2000, 	4*KB,               RW,  None, None),
    RegionInfo("SPIS1",	        0xFFE0_3000, 	4*KB,               RW,  None, None),
    RegionInfo("SPIM0",	        0xFFF0_0000, 	4*KB,               RW,  None, None),
    RegionInfo("SPIM1",	        0xFFF0_1000, 	4*KB,               RW,  None, None),
    RegionInfo("SCANMGR",	        0xFFF0_2000, 	4*KB,               RW,  None, None),
    RegionInfo("ROM",	            0xFFFD_0000, 	64*KB,              RW,  None, None),
    RegionInfo("MPU",	            0xFFFE_C000, 	8*KB,               RW,  None, None),
    RegionInfo("MPUL2",	        0xFFFE_F000, 	4*KB,               RW,  None, None),
    // OCRAM (on-chip RAM): 0xFFFF_0000 size 0x1_0000. Note: this region can be aliased to the Boot
    // Region (address 0) after the system is running.
    RegionInfo("SRAM 64K",        0xFFFF_0000,    64*KB,              RWX, None, None),
];

pub struct CycloneVBuilder {
    initial_cbar: u32,
    initial_vbar: u32,
}

impl CycloneVBuilder {
    pub fn new(cbar: u32, vbar: u32) -> Self {
        if cbar > 0xFFFF_E000 {
            panic!("Invalid CBAR address greater than 0xFFFF_E000: {cbar:#x}");
        }
        Self {
            initial_cbar: cbar,
            initial_vbar: vbar,
        }
    }
}

impl Default for CycloneVBuilder {
    fn default() -> Self {
        Self {
            initial_cbar: 0,
            initial_vbar: 0x0010_0040,
        }
    }
}

impl ProcessorImpl for CycloneVBuilder {
    fn init(&self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        // Initialize ourself before we move on to the peripherals.
        // Vector Base Address Register (VBAR):
        // The location of the exception vectors is configured by the external
        // configuration signal `VINITHI[N:0]`. The pin is sampled at processor reset,
        // and it sets the initial value of `SCTLR.V` (the System Control Register's
        // Vectors bit - bit 13). This register is accessed using CP15.
        // Vectors bit:
        //  - 0 -> Normal exception vectors. Base address is held in the Vector Base
        //         Address Register (VBAR).
        //  - 1 -> High exception vectors (Hivecs), base address 0xFFFF0000. This base
        //         address cannot be remapped.
        if self.initial_vbar == 0xFFFF_0000_u32 {
            set_sctlr_vbit(proc.core.cpu.as_mut());
        } else {
            set_vbar(proc.core.cpu.as_mut(), self.initial_vbar);
        }

        // Reset the Current Program Status Register (CPSR).
        reset_cpsr(proc.core.cpu.as_mut());

        // Configuration Base Address Register (CBAR):
        //  - Specifies the base address for Timers, Watchdogs, Interrupt Controller,
        //    and SCU registers.
        //  - All registers accessible by all Cortex-A9 processors within the Cortex-A9 MPCore are
        //    grouped into two contiguous 4KB pages accessed through a dedicated internal bus. The
        //    base address of these pages is defined by the pins `PERIPHBASE[31:13]`.
        //  - This value can be retrieved by a Cortex-A9 processor using CP15.
        //  - The base address can be anywhere from 0x0000_0000 to 0xFFFF_E000.
        set_cbar(proc.core.cpu.as_mut(), self.initial_cbar);

        Ok(())
    }

    fn build(&self, args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError> {
        let cpu: Box<dyn CpuBackend> = match args.backend {
            Backend::Pcode => Box::new(PcodeBackend::new_engine_config(
                ArmVariants::ArmCortexA9,
                ArchEndian::LittleEndian,
                &args.into(),
            )),
            Backend::Unicorn => Box::new(UnicornBackend::new_engine_exception(
                Arch::Arm,
                ArmVariants::ArmCortexA9,
                ArchEndian::LittleEndian,
                args.exception,
            )),
        };

        let mut mmu = Mmu::default_region_store();

        self.setup_address_space(&mut mmu)?;

        let gic = Gic::default();
        gic.initialize(self.initial_vbar, self.initial_cbar)?;

        let peripherals: Vec<Box<dyn Peripheral>> = vec![
            Box::new(CycloneVSDMMC::new()),
            Box::new(ClockManager::new()),
            Box::new(UartController::new(get_uarts())),
        ];

        let mut hints = LoaderHints::new();
        hints.insert("arch".to_string().into_boxed_str(), Box::new(Arch::Arm));

        Ok(ProcessorBundle {
            cpu,
            mmu,
            event_controller: Box::new(gic),
            peripherals,
            loader_hints: hints,
        })
    }
}

impl CycloneVBuilder {
    fn setup_address_space(&self, mmu: &mut Mmu) -> Result<(), UnknownError> {
        let mut regions = Vec::new();

        for rg in ADDRESS_MAP.iter() {
            debug!("{}", rg);
            let RegionInfo(_, base, size, perms, init, alias_base) = *rg;
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
}

const SCTLR_VBIT_IDX: usize = 13;
const SCTLR_VBIT_MASK: u64 = 1u64 << SCTLR_VBIT_IDX;

/// Set the configuration base address coprocessor register (CBAR).
fn set_cbar(cpu: &mut dyn CpuBackend, cba: u32) {
    cpu.write_register(
        arm_coproc_registers::CBAR,
        arm_coproc_registers::CBAR.with_value(cba as u64),
    )
    .unwrap();
}

/// Set the vector base address coprocessor register (VBAR).
fn set_vbar(cpu: &mut dyn CpuBackend, vba: u32) {
    trace!("Setting VBAR to {:#08X}.", vba);

    // VBAR is a banked register, so there are secure and non-secure versions of it.
    // XXX For the time being we do both, but this may not always be valid.
    // Do secure mode first.
    cpu.write_register(
        arm_coproc_registers::VBAR,
        arm_coproc_registers::VBAR.with_value(vba as u64),
    )
    .unwrap();
    // Now non-secure mode.
    //vbar_desc.ns_mode = true;
}

/// Set the vectors bit in the system control coprocessor register (SCTLR).
fn set_sctlr_vbit(cpu: &mut dyn CpuBackend) {
    trace!("Setting SCTLR V-bit.");

    // Read the initial SCTLR value.
    let mut sctlr_val = cpu
        .read_register::<CoProcessorValue>(arm_coproc_registers::SCTLR)
        .unwrap();
    sctlr_val.value |= SCTLR_VBIT_MASK;

    // SCTLR is a banked register, so there are secure and non-secure versions of it.
    // XXX For the time being we do both, but this may not always be valid.
    // Do secure mode first.
    cpu.write_register(arm_coproc_registers::SCTLR, sctlr_val)
        .unwrap();
}

#[cfg(test)]
mod tests {
    use styx_core::cpu::arch::arm::ArmRegister;

    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_can_build_cpu_engine() {
        let cpu_result = ProcessorBuilder::default()
            .with_builder(CycloneVBuilder::default())
            .build();
        assert!(cpu_result.is_ok());
    }

    #[test]
    #[cfg_attr(asan, ignore)]
    #[cfg_attr(miri, ignore)]
    fn test_setting_sctlr_vbit() {
        let mut proc = ProcessorBuilder::default()
            .with_builder(CycloneVBuilder::default())
            .build()
            .unwrap();

        // Verify that V-bit is not set initially.
        let sctlr_val = proc
            .core
            .cpu
            .read_register::<CoProcessorValue>(arm_coproc_registers::SCTLR)
            .unwrap();
        assert_eq!(sctlr_val.value & SCTLR_VBIT_MASK, 0);

        set_sctlr_vbit(proc.core.cpu.as_mut());

        // Ensure the V-bit was set.
        let sctlr_val = proc
            .core
            .cpu
            .read_register::<CoProcessorValue>(arm_coproc_registers::SCTLR)
            .unwrap();
        assert_eq!(sctlr_val.value & SCTLR_VBIT_MASK, SCTLR_VBIT_MASK);
    }

    #[test]
    #[cfg_attr(asan, ignore)]
    #[cfg_attr(miri, ignore)]
    fn test_setting_vbar_cbar() {
        const TEST_VAL: u64 = 0xDECAFB00;

        let mut proc = ProcessorBuilder::default()
            .with_builder(CycloneVBuilder::default())
            .build()
            .unwrap();

        // Test VBAR.
        set_vbar(proc.core.cpu.as_mut(), TEST_VAL as u32);

        // First check secure mode.
        let vbar = proc
            .core
            .cpu
            .read_register::<CoProcessorValue>(arm_coproc_registers::VBAR)
            .unwrap();
        assert_eq!(vbar.value, TEST_VAL);

        // Test CBAR.
        set_cbar(proc.core.cpu.as_mut(), TEST_VAL as u32);

        let cbar = proc
            .core
            .cpu
            .read_register::<CoProcessorValue>(arm_coproc_registers::CBAR)
            .unwrap();
        assert_eq!(cbar.value, TEST_VAL);
    }

    #[test]
    fn test_coproc_instructions() {
        styx_core::prelude::logging::init_logging();

        let code_bytes: &[u8] = &[
            0x10, 0x7f, 0x11, 0xee, // mrc p15, 0, r7, c1, c0, 0
            0x02, 0x8a, 0x87, 0xe3, // orr r8, r7, #0x2000
            0x10, 0x8f, 0x01, 0xee, // mcr p15, 0, r8, c1, c0, 0
            0x10, 0x7f, 0x11, 0xee, // mrc p15, 0, r7, c1, c0, 0
            0x10, 0x7f, 0x9f, 0xee, // mrc p15, 4, r7, c15, c0, 0
            0x10, 0x7f, 0x1c, 0xee, // mrc p15, 0, r7, c12, c0, 0
        ];

        let mut proc = ProcessorBuilder::default()
            .with_builder(CycloneVBuilder::default())
            .build()
            .unwrap();

        proc.core.mmu.write_code(0x00100000, code_bytes).unwrap();
        proc.core.cpu.set_pc(0x00100000).unwrap();

        debug!("Reading initial value from SCTLR.");
        proc.run(1).unwrap();
        let r7 = proc.core.cpu.read_register::<u32>(ArmRegister::R7).unwrap();
        assert_eq!(r7, 0);

        debug!("Setting sctlr vbit and reading back");
        proc.run(3).unwrap();
        let r7 = proc.core.cpu.read_register::<u32>(ArmRegister::R7).unwrap();
        assert_eq!(r7, 0x2000);

        debug!("Reading cbar");
        proc.run(1).unwrap();
        let r7 = proc.core.cpu.read_register::<u32>(ArmRegister::R7).unwrap();
        assert_eq!(r7, 0);

        debug!("Reading vbar");
        proc.run(1).unwrap();
        let r7 = proc.core.cpu.read_register::<u32>(ArmRegister::R7).unwrap();
        assert_eq!(r7, 0x100040);
    }
}
