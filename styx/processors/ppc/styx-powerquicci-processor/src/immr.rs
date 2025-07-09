// SPDX-License-Identifier: BSD-2-Clause
//! IMMR definition + low level implementation for MPC866m
//!
//! The register definitions come from the `MPC866 PowerQUICC Family Reference Manual`,
//! Table 2.1 "Internal Memory Map"
#![allow(dead_code)]
#![allow(clippy::identity_op)] // makes all the definitions uniform
use bilge::prelude::*;
use styx_core::sync::lazy_static;
use thiserror::Error;

#[allow(unused_imports)]
pub use immr_defs::*; // re-export these

#[derive(Debug, Error)]
pub enum ImmrSearchError {
    #[error("Search did not fit in candidate register: `{0}`")]
    ExceedsRegisterBounds(&'static str),
    #[error("Offset `{0:#x}` is invalid for IMMR")]
    NotInRange(u32),
}

pub const DEFAULT_BASE_ADDRESS: u64 = 0xFF00_0000;

lazy_static! {
    pub static ref IMMR_REGION_LEN: usize = {
        let first = IMMR_REGISTERS.first().unwrap();
        let last = IMMR_REGISTERS.last().unwrap();

        (last.end() + 1 + first.offset()) as usize
    };
}

/// Searches the [`IMMR_REGISTERS`](static@IMMR_REGISTERS) for a valid parent that owns the
/// entirety of the provided search range contained in `[offset, offset + size)`
///
/// ```rust
/// use styx_powerquicci_processor::immr;
///
/// // fails to find offset in range
/// assert!(immr::register_search(0x99999999, 1).is_err());
/// // search range does not fit in the register @ `0x00`
/// assert!(immr::register_search(0, 0x4000).is_err());
/// // successfully finds register
/// assert!(immr::register_search(0, 4).is_ok());
/// ```
pub fn register_search(
    offset: u32,
    size: u32,
) -> Result<&'static ImmrRegisterDescriptor, ImmrSearchError> {
    // look through all the registers
    for reg in IMMR_REGISTERS.iter() {
        // get the valid range for the current register
        let reg_range = reg.offset()..=reg.end();

        // is the start offset valid
        if reg_range.contains(&offset) {
            // is the entire search range valid in a single register
            // (it MUST be)
            if reg_range.contains(&offset.saturating_add(size.saturating_sub(1))) {
                return Ok(reg);
            }

            // reg start was valid, but the search range
            // doesnt fit in one register
            return Err(ImmrSearchError::ExceedsRegisterBounds(reg.abbreviation()));
        }
    }

    Err(ImmrSearchError::NotInRange(offset))
}

/// Defines a `static ImmrRegisterDescriptor` type
macro_rules! immr_registers {
    ($($abrev:expr, $name:expr, $offset:expr, $size:expr);* $(;)?) => {
        paste! {
            pub static IMMR_REGISTERS: &[&'static ImmrRegisterDescriptor] = &[$( &[<$abrev RegisterDesc>] ),* ];
        }

        $(
            paste! {
                #[allow(non_snake_case, non_upper_case_globals)]
                pub static [<$abrev RegisterDesc>]: ImmrRegisterDescriptor = ImmrRegisterDescriptor {
                    offset: $offset,
                    byte_size: $size,
                    abbreviation: $abrev,
                    name: $name,
                };

            }
        )*
    };
}

#[derive(Debug)]
pub struct Immr {}

#[derive(Debug, Default, Clone)]
pub struct ImmrRegisterDescriptor {
    offset: u32,
    byte_size: u32,
    abbreviation: &'static str,
    name: &'static str,
}

impl ImmrRegisterDescriptor {
    pub fn offset(&self) -> u32 {
        self.offset
    }

    pub fn byte_size(&self) -> u32 {
        self.byte_size
    }

    pub fn abbreviation(&self) -> &'static str {
        self.abbreviation
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    /// End address that belongs to the descriptor
    pub fn end(&self) -> u32 {
        if self.byte_size > 0 {
            self.offset + (self.byte_size - 1)
        } else {
            panic!("`{}` is a register with no size!", self.name);
        }
    }
}

impl PartialEq for ImmrRegisterDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.offset.eq(&other.offset)
    }
}

impl Eq for ImmrRegisterDescriptor {}

impl PartialOrd for ImmrRegisterDescriptor {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.offset.cmp(&other.offset))
    }
}

impl Ord for ImmrRegisterDescriptor {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.offset.cmp(&other.offset)
    }
}

#[rustfmt::skip] // so the macro invocations are all on one line
mod immr_defs {
    use paste::paste;
    use super::ImmrRegisterDescriptor;

    immr_registers! {
    // General System Interface Unit
        "SIUMCR", "SIU Module Configuration Register", 0x0, 4;
        "SYPCR", "System Protection Control Register", 0x4, 4;
        "RESERVED0", "Reserved0", 0x8, 6;
        "SWSR", "Software Service Register", 0xe, 2;
        "SIPEND", "SIU Interrupt Pending Register", 0x10, 4;
        "SIMASK", "SIU Interrupt Mask Register", 0x14, 4;
        "SIEL", "SIU Interrupt Edge/Level Register", 0x18, 4;
        "SIVEC", "SIU Interrupt Vector Register", 0x1c, 4;
        "TESR", "Transfer Error Status Register", 0x20, 4;
        "RESERVED1", "Reserved1", 0x24, 12;
        "SDCR", "SDMA Configuration Register", 0x30, 4;
        "RESERVED2", "Reserved2", 0x34, 76;
    // PCMCIA
        "PBR0", "PCMCIA interface base register 0", 0x80, 4;
        "POR0", "PCMCIA interface option register 0", 0x84, 4;
        "PBR1", "PCMCIA interface base register 1", 0x88, 4;
        "POR1", "PCMCIA interface option register 1", 0x8c, 4;
        "PBR2", "PCMCIA interface base register 2", 0x90, 4;
        "POR2", "PCMCIA interface option register 2", 0x94, 4;
        "PBR3", "PCMCIA interface base register 3", 0x98, 4;
        "POR3", "PCMCIA interface option register 3", 0x9c, 4;
        "PBR4", "PCMCIA interface base register 4", 0xa0, 4;
        "POR4", "PCMCIA interface option register 4", 0xa4, 4;
        "PBR5", "PCMCIA interface base register 5", 0xa8, 4;
        "POR5", "PCMCIA interface option register 5", 0xac, 4;
        "PBR6", "PCMCIA interface base register 6", 0xb0, 4;
        "POR6", "PCMCIA interface option register 6", 0xb4, 4;
        "PBR7", "PCMCIA interface base register 7", 0xb8, 4;
        "POR7", "PCMCIA interface option register 7", 0xbc, 4;
        "RESERVED3", "Reserved3", 0xc0, 32;
        "PGCRA", "PCMCIA interface general control register A", 0xe0, 4;
        "PGCRB", "PCMCIA interface general control register B", 0xe4, 4;
        "PSCR", "PCMCIA status changed regisster", 0xe8, 4;
        "RESERVED4", "Reserved4", 0xec, 4;
        "PIPR", "PCMCIA interface input pins register", 0xf0, 4;
        "RESERVED5", "Reserved5", 0xf4, 4;
        "PER", "PCMCIA interface enable register", 0xf8, 4;
        "RESERVED6", "Reserved6", 0xfc, 4;
    // Memory Controller
        "BR0", "Base Register Bank 0", 0x100, 4;
        "OR0", "Option Register Bank 0", 0x104, 4;
        "BR1", "Base Register Bank 1", 0x108, 4;
        "OR1", "Option Register Bank 1", 0x10c, 4;
        "BR2", "Base Register Bank 2", 0x110, 4;
        "OR2", "Option Register Bank 2", 0x114, 4;
        "BR3", "Base Register Bank 3", 0x118, 4;
        "OR3", "Option Register Bank 3", 0x11c, 4;
        "BR4", "Base Register Bank 4", 0x120, 4;
        "OR4", "Option Register Bank 4", 0x124, 4;
        "BR5", "Base Register Bank 5", 0x128, 4;
        "OR5", "Option Register Bank 5", 0x12c, 4;
        "BR6", "Base Register Bank 6", 0x130, 4;
        "OR6", "Option Register Bank 6", 0x134, 4;
        "BR7", "Base Register Bank 7", 0x138, 4;
        "OR7", "Option Register Bank 7", 0x13c, 4;
        "RESERVED7", "Reserved", 0x140, 36;
        "MAR", "Memory Address Register", 0x164, 4;
        "MCR", "Memory Command Register", 0x168, 4;
        "RESERVED8", "Reserved8", 0x16c, 4;
        "MAMR", "Machine A Mode Register", 0x170, 4;
        "MBMR", "Machine B Mode Register", 0x174, 4;
        "MSTAT", "Memory Status Register", 0x178, 2;
        "MPTPR", "Memory Periodic Timer Prescaler", 0x17a, 2;
        "MDR", "Memory Data Register", 0x17c, 4;
        "RESERVED9", "Reserved9", 0x180, 128;
    // System Integration Timers
        "TBSCR", "Timebase Status and Control Register", 0x200, 2;
        "RESERVED10", "Reserved10", 0x202, 2;
        "TBREFA", "Timebase Reference Register A", 0x204, 4;
        "TBREFB", "Timebase Reference Register B", 0x208, 4;
        "RESERVED11", "Reserved11", 0x20c, 20;
        "RESERVED12", "Reserved12", 0x220, 2;
        "RESERVED13", "Reserved13", 0x222, 2;
        "RESERVED14", "Reserved14", 0x224, 4;
        "RESERVED15", "Reserved15", 0x228, 4;
        "RESERVED16", "Reserved16", 0x22c, 4;
        "RESERVED17", "Reserved17", 0x230, 16;
        "PISCR", "Periodic Interrupt Status and Control Register", 0x240, 2;
        "RESERVED18", "Reserved18", 0x242, 2;
        "PITC", "Periodic Interrupt Count Register", 0x244, 4;
        "PITR", "Periodic Interrupt Timer Register", 0x248, 4;
        "RESERVED19", "Reserved19", 0x24c, 52;
    // Clocks and Reset
        "SCCR", "System Clock Reset Control Register", 0x280, 4;
        "PLPRCR", "PLL and Reset Control Register", 0x284, 4;
        "RSR", "Reset Status Register", 0x288, 4;
        "RESERVED20", "Reserved20", 0x28c, 116;
    // System Integration Timers Keys
        "TBSCRK", "Timebase Status and Control Register Key", 0x300, 4;
        "TBREFAK", "Timebase Reference Register A Key", 0x304, 4;
        "TBREFBK", "Timebase Reference Register B Key", 0x308, 4;
        "TBK", "Timebase/Decrementer Register Key", 0x30c, 4;
        "RESERVED21", "Reserved21", 0x310, 16;
        "RESERVED22", "Reserved22", 0x320, 4;
        "RESERVED23", "Reserved23", 0x324, 4;
        "RESERVED24", "Reserved24", 0x328, 4;
        "RESERVED25", "Reserved25", 0x32c, 4;
        "RESERVED26", "Reserved26", 0x330, 16;
        "PISCRK", "Periodic Interrupt Status and Control Register Key", 0x340, 4;
        "PITCK", "Periodic Interrupt Count Register Key", 0x344, 4;
        "RESERVED27", "Reserved27", 0x348, 56;
    // Clocks and Reset Keys
        "SCCRK", "System Clock Control Key", 0x380, 4;
        "PLPRCRK", "PLL and Reset Control Register Key", 0x384, 4;
        "RSRK", "Reset Status Register Key", 0x388, 4;
        "RESERVED28", "Reserved28", 0x38c, 1236;
    // I2C Controller
        "I2MOD", "I2C Mode Register", 0x860, 2;
        "RESERVED29", "Reserved29", 0x862, 2;
        "I2ADD", "I2C Address Register", 0x864, 2;
        "RESERVED30", "Reserved30", 0x866, 2;
        "I2BRG", "I2C BRG Register", 0x868, 2;
        "RESERVED31", "Reserved31", 0x86a, 2;
        "I2COM", "I2C Command Register", 0x86c, 2;
        "RESERVED32", "Reserved32", 0x86e, 2;
        "I2CER", "I2C Event Register", 0x870, 2;
        "RESERVED33", "Reserved33", 0x872, 2;
        "I2CMR", "I2C Mask Register", 0x874, 2;
        "RESERVED34", "Reserved34", 0x876, 138;
    // DMA
        "RESERVED35", "Reserved35", 0x900, 4;
        "SDAR", "SDMA Address Register", 0x904, 4;
    // this is getting remapped to size 2 due to limitations of the target,
    // see next comment
        "SDSR", "SMDA Status Register", 0x908, 2;
        "RESERVED36", "Reserved36", 0x90a, 2;
    // this is getting remapped to size 2 due to limitations of the target,
    // see next comment
        "SDMR", "SDMA Mask Register", 0x90c, 2;
    // the smallest write is a u16, so this `reserved37` *should* start
    // at 0x90d, but starts at 0x90e to accomadate the reality of the target
        "RESERVED37", "Reserved37", 0x90e, 2;
    // this is getting remapped to size 2 due to limitations of the target,
    // see previous comment
        "IDSR1", "IDMA1 Status Register", 0x910, 2;
        "RESERVED38", "Reserved38", 0x912, 2;
        "IDMR1", "IDMA1 Mask Register", 0x914, 2;
        "RESERVED39", "Reserved39", 0x916, 2;
        "IDSR2", "IDMA2 Status Register", 0x918, 2;
        "RESERVED40", "Reserved40", 0x91a, 2;
        "IDMR2", "IDMA2 Mask Register", 0x91c, 2;
        "RESERVED41", "Reserved41", 0x91e, 18;
    // Communications Processor Module Interrupt Control
        "CIVR", "CPM INterrupt Vector Register", 0x930, 2;
        "RESERVED42", "Reerved42", 0x932, 14;
        "CICR", "CPM Interrupt Configuration Register", 0x940, 4;
        "CIPR", "CPM Interrupt Pending Register", 0x944, 4;
        "CIMR", "CPM Interrupt Mask Register", 0x948, 4;
        "CISR", "CPM In-Service Register", 0x94c, 4;
    // Input / Output Port
        "PADIR", "Port A Data Direction Register", 0x950, 2;
        "PAPAR", "Port A Pin Assignment Register", 0x952, 2;
        "PAODR", "Port A Open Drain Register", 0x954, 2;
        "PADAT", "Port A Data Register", 0x956, 2;
        "RESERVED43", "Reserved43", 0x958, 8;
        "PCDIR", "Port C Data Direction Register", 0x960, 2;
        "PCPAR", "Port C Pin Assignment Register", 0x962, 2;
        "PCSO", "Port C Special Options Register", 0x964, 2;
        "PCDAT", "Port C Data Register", 0x966, 2;
        "PCINT", "Port C Interrupt Control Register", 0x968, 2;
        "RESERVED44", "Reserved44", 0x96a, 6;
        "PDDIR", "Port D Data Direction Register", 0x970, 2;
        "PDPAR", "Port D Pin Assignment Register", 0x972, 2;
        "RESERVED45", "Reserved45", 0x974, 2;
        "PDDAT", "Port D Data Register", 0x976, 2;
        "UTMODE", "UTOPIA Mode Register", 0x978, 4;
        "RESERVED46", "Reserved46", 0x97c, 4;
    // CPM General Purpose Timers
        "TGCR", "Timer Global Configuration Register", 0x980, 2;
        "RESERVED47", "Reserved47", 0x982, 14;
        "TMR1", "Timer 1 Mode Register", 0x990, 2;
        "TMR2", "Timer 2 Mode Register", 0x992, 2;
        "TRR1", "Timer 1 Reference Register", 0x994, 2;
        "TRR2", "Timer 2 Reference Register", 0x996, 2;
        "TCR1", "Timer 1 Capture Register", 0x998, 2;
        "TCR2", "TImer 2 Capture Register", 0x99a, 2;
        "TCN1", "Timer 1 Counter", 0x99c, 2;
        "TCN2", "Timer 2 Counter", 0x99e, 2;
        "TMR3", "Timer 3 Mode Register", 0x9a0, 2;
        "TMR4", "Timer 4 Mode Register", 0x9a2, 2;
        "TRR3", "Timer 3 Reference Register", 0x9a4, 2;
        "TRR4", "Timer 4 Reference Register", 0x9a6, 2;
        "TCR3", "Timer 3 Capture Register", 0x9a8, 2;
        "TCR4", "Timer 4 Capture Register", 0x9aa, 2;
        "TCN3", "Timer 3 Counter", 0x9ac, 2;
        "TCN4", "Timer 4 Counter", 0x9ae, 2;
        "TER1", "Timer 1 Event Register", 0x9b0, 2;
        "TER2", "Timer 2 Event Register", 0x9b2, 2;
        "TER3", "Timer 3 Event Register", 0x9b4, 2;
        "TER4", "Timer 4 Event Register", 0x9b6, 2;
        "RESERVED48", "Reserved48", 0x9b8, 8;
    // Communications Processor
        "CPCR", "Communications Processor Command Register", 0x9c0, 2;
        "RESERVED49", "Reserved49", 0x9c2, 2;
        "RCCR", "RISC Controller Configuration Register", 0x9c4, 2;
        "RESERVED50", "Reserved50", 0x9c6, 1;
        "RMDS", "RISC Microcode Development Support Control Register", 0x9c7, 1;
        "RESERVED51", "Reserved51", 0x9c8, 4;
        "RCTR1", "RISC Controller Trap Register 1", 0x9cc, 2;
        "RCTR2", "RISC Controller Trap Register 2", 0x9ce, 2;
        "RCTR3", "RISC Controller Trap Register 3", 0x9d0, 2;
        "RCTR4", "RISC Controller Trap Register 4", 0x9d2, 2;
        "RESERVED52", "Reserved52", 0x9d4, 2;
        "RTER", "RISC Timer Event Register", 0x9d6, 2;
        "RESERVED53", "Reserved53", 0x9d8, 2;
        "RTMR", "RISC Timers Mask Register", 0x9da, 2;
        "RESERVED54", "Reserved54", 0x9dc, 20;
    // Baud Rate Generators
        "BRGC1", "BRG1 Configuration Register", 0x9f0, 4;
        "BRGC2", "BRG2 Configuration Register", 0x9f4, 4;
        "BRGC3", "BRG3 Configuration Register", 0x9f8, 4;
        "BRGC4", "BRG4 Configuration Register", 0x9fc, 4;
    // Serial Communications Controller 1 (SCC1)
        "GSMR_L1", "SCC1 General Mode Register (L)", 0xa00, 4;
        "GSMR_H1", "SCC1 General Mode Register (H)", 0xa04, 4;
        "PSMR1", "SCC1 Protocol Specific Mode Register", 0xa08, 2;
        "RESERVED55", "Reserved55", 0xa0a, 2;
        "TODR1", "SCC1 Transmit-on-Demand Register", 0xa0c, 2;
        "DSR1", "SCC1 Data Synchronization Register", 0xa0e, 2;
        "SCCE1", "SCC1 Event Register", 0xa10, 2;
        "RESERVED56", "Reserved56", 0xa12, 2;
        "SCCM1", "SCC1 Mask Register", 0xa14, 2;
        "RESERVED57", "Reserved57", 0xa16, 1;
        "SCCS1", "SCC1 Status Register", 0xa17, 1;
        "RESERVED58", "Reserved58", 0xa18, 8;
    // Serial Communications Controller 2 (SCC2)
        "GSMR_L2", "SCC2 General Mode Register (L)", 0xa20, 4;
        "GSMR_H2", "SCC2 General Mode Register (H)", 0xa24, 4;
        "PSMR2", "SCC2 Protocol Specific Mode Register", 0xa28, 2;
        "RESERVED59", "Reserved59", 0xa2a, 2;
        "TODR2", "SCC2 Transmit on Demand Register", 0xa2c, 2;
        "DSR2", "SCC2 Data Synchronization Register", 0xa2e, 2;
        "SCCE2", "SCC2 Event Register", 0xa30, 2;
        "RESERVED60", "Reserved60", 0xa32, 2;
        "SCCM2", "SCC2 Mask Register", 0xa34, 2;
        "RESERVED61", "Reserved61", 0xa36, 1;
        "SCCS2", "SCC2 Status Register", 0xa37, 1;
        "RESERVED62", "Reserved62", 0xa38, 8;
    // Serial Communications Controller 3 (SCC3)
        "GSMR_L3", "SCC3 General Mode Register (L)", 0xa40, 4;
        "GSMR_H3", "SCC3 General Mode Register (H)", 0xa44, 4;
        "PSMR3", "SCC3 Protocol Specific Mode Register", 0xa48, 2;
        "RESERVED63", "Reserved63", 0xa4a, 2;
        "TODR3", "SCC3 Transmit on Demand Register", 0xa4c, 2;
        "DSR3", "SCC3 Data Synchronization Register", 0xa4e, 2;
        "SCCE3", "SCC3 Event Register", 0xa50, 2;
        "RESERVED64", "Reserved64", 0xa52, 2;
        "SCCM3", "SCC3 Mask Register", 0xa54, 2;
        "RESERVED65", "Reserved65", 0xa56, 1;
        "SCCS3", "SCC3 Status Register", 0xa57, 1;
        "RESERVED66", "Reserved66", 0xa58, 8;
    // Serial Communications Controller 4 (SCC4)
    	  "GSMR_L4", "SCC4 General Mode Register (L)", 0xa60, 4;
    	  "GSMR_H4", "SCC4 General Mode Register (H)", 0xa64, 4;
    	  "PSMR4", "SCC4 Protocol Specific Mode Register", 0xa68, 2;
    	  "RESERVED67", "Reserved67", 0xa6a, 2;
    	  "TODR4", "SCC4 Transmit on Demand Register", 0xa6c, 2;
    	  "DSR4", "SCC4 Data Synchronization Register", 0xa6e, 2;
    	  "SCCE4", "SCC4 Event Register", 0xa70, 2;
    	  "RESERVED68", "Reserved68", 0xa72, 2;
    	  "SCCM4", "SCC4 Mask Register", 0xa74, 2;
    	  "RESERVED69", "Reserved69", 0xa76, 1;
    	  "SCCS4", "SCC4 Status Register", 0xa77, 1;
        "RESERVED70", "Reserved71", 0xa78, 10;
    // Serial Management Controller 1 (SMC1)
    	  "SMCMR1", "SMC1 Mode Register", 0xa82, 2;
    	  "RESERVED71", "Reserved71", 0xa84, 2;
    	  "SMCE1", "SMC1 Event Register", 0xa86, 1;
    	  "RESERVED72", "Reserved72", 0xa87, 3;
    	  "SMCM1", "SMC1 Mask Register", 0xa8a, 1;
    	  "RESERVED73", "Reserved73", 0xa8b, 7;
    // Serial Management Controller 2 (SMC2)
    	  "SMCMR2", "SMC2 Mode Register", 0xa92, 2;
    	  "RESERVED74", "Reserved74", 0xa94, 2;
    	  "SMCE2", "SMC2 Event Register", 0xa96, 1;
    	  "RESERVED75", "Reserved75", 0xa97, 3;
    	  "SMCM2", "SMC2 Mask Register", 0xa9a, 1;
    	  "RESERVED76", "Reserved76", 0xa9b, 5;
    // Serial Peripheral Interface (SPI)
    	  "SPMODE", "SPI Mode Register", 0xaa0, 2;
    	  "RESERVED77", "Reserved77", 0xaa2, 4;
    	  "SPIE", "SPI Event Register", 0xaa6, 1;
    	  "RESERVED78", "Reserved78", 0xaa7, 3;
    	  "SPIM", "SPI Mask Register", 0xaaa, 1;
    	  "RESERVED79", "Reserved79", 0xaab, 2;
    	  "SPCOM", "SPI Command Register", 0xaad, 1;
    	  "RESERVED80", "Reserved80", 0xaae, 4;
    // Parallel Interface Port (PIP) and Port B
    	  "PIPC", "PIP Configuration Register", 0xab2, 2;
    	  "RESERVED81", "Reserved81", 0xab4, 2;
    	  "PTPR", "PIP Timing Parameters Register", 0xab6, 2;
    	  "PBDIR", "Port B Data Direction Register", 0xab8, 4;
    	  "PBPAR", "Port B Pin Assignment Register", 0xabc, 4;
    	  "PBODR", "Port B Open Drain Register", 0xac0, 4;
    	  "PBDAT", "Port B Data Register", 0xac4, 4;
    	  "RESERVED82", "Reserved82", 0xac8, 24;
    // Serial Interface (SI)
    	  "SIMODE", "SI Mode Register", 0xae0, 4;
    	  "SIGMR", "SI Global Mode Register", 0xae4, 1;
    	  "RESERVED83", "Reserved83", 0xae5, 1;
    	  "SISTR", "SI Status Register", 0xae6, 1;
    	  "SICMR", "SI Command Register", 0xae7, 1;
    	  "RESERVED84", "Reserved84", 0xae8, 4;
    	  "SICR", "SI Clock Router Register", 0xaec, 4;
    	  "SIRP", "Serial Interface RAM Pointer Register", 0xaf0, 4;
    	  "RESERVED85", "Reserved85", 0xaf4, 268;
    	  "SIRAM", "SI Routing RAM", 0xc00, 512;
    // Fast Ethernet Controller (FEC)
    	  "ADDR_LOW", "ADDR_LOW register", 0xe00, 4;
    	  "ADDR_HIGH", "ADDR_HIGH register", 0xe04, 4;
    	  "HASH_TABLE_HIGH", "HASH_TABLE_HIGH", 0xe08, 4;
    	  "HASH_TABLE_LOW", "HASH_TABLE_LOW", 0xe0c, 4;
    	  "R_DES_START", "R_DES_START", 0xe10, 4;
    	  "X_DES_START", "X_DES_START", 0xe14, 4;
    	  "R_BUFF_SIZE", "R_BUFF_SIZE", 0xe18, 4;
    	  "RESERVED86", "Reserved86", 0xe1c, 36;
    	  "ECNTRL", "ECNTRL", 0xe40, 4;
    	  "IEVENT", "IEVENT", 0xe44, 4;
    	  "IMASK", "IMASK", 0xe48, 4;
    	  "IVEC", "IVEC", 0xe4c, 4;
    	  "R_DES_ACTIVE", "R_DES_ACTIVE", 0xe50, 4;
    	  "X_DES_ACTIVE", "X_DES_ACTIVE", 0xe54, 4;
    	  "RESERVED87", "Reserved87", 0xe58, 40;
    	  "MII_DATA", "MII_DATA", 0xe80, 4;
    	  "MII_SPEED", "MII_SPEED", 0xe84, 4;
    // NOTE: the manual specifies this Reserved size as `220`
    	  "RESERVED88", "Reserved88", 0xe88, 68;
    	  "R_BOUND", "R_BOUND", 0xecc, 4;
    // NOTE: the manual specifies this offset as `0xed0` with size 4,
    // and omits the existence of a RESERVED field following it
    	  "R_FSTART", "R_FSTART", 0xed0, 4;
    	  "OMITTED_RESERVED1", "Omitted R_FSTART Reserved", 0xed4, 16;
    // NOTE: the manual specifies this offset as `0xee4` with size 4,
    // and omits the existence of a RESERVED field following it
    	  "X_WMRK", "X_WMRK", 0xee4, 4;
    	  "OMMITED_RESERVED2", "Omitted X_WMRK Reserved", 0xee8, 4;
    	  "X_FSTART", "X_FSTART", 0xeec, 4;
    	  "RESERVED89", "Reserved89", 0xef0, 68;
    	  "FUN_CODE", "FUN_CODE", 0xf34, 4;
    	  "RESERVED90", "Reserved90", 0xf38, 12;
    	  "R_CNTRL", "R_CNTRL", 0xf44, 4;
    	  "R_HASH", "R_HASH", 0xf48, 4;
    	  "RESERVED91", "Reserved91", 0xf4c, 56;
    	  "X_CNTRL", "X_CNTRL", 0xf84, 4;
    // NOTE: the manual defines this as offset 0xf88, size 4215, *off by 1*
        "RESERVED92", "Reserved92", 0xf88, 4216;
    // Dual-Port RAM (DPRAM)
        "DPRAM", "Dual-Port System RAM", 0x2000, 4096;
        "DPRAMEXP", "Dual-Port System RAM expansion", 0x3000, 3072;
        "PRAM", "Dual-Port Parameter RAM", 0x3c00, 1024;
    }
}

#[bitsize(64)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct EthernetRxBufferDescriptor {
    header: EthernetRxBufferDescriptorHeader,
    data_length: u16,
    buffer_pointer: u32,
}

#[bitsize(64)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct EthernetTxBufferDescriptor {
    header: EthernetTxBufferDescriptorHeader,
    data_length: u16,
    buffer_pointer: u32,
}

#[bitsize(16)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct EthernetRxBufferDescriptorHeader {
    /// Empty. Written by the FEC and user. Note that is the software driver
    /// sets `RxBD[E]`, it should then write to R_DES_ACTIVE
    /// - 0: The buffer associated with this BD is filled with received data, or
    ///      reception was aborted due to an error. The satatus and length fields
    ///      have been updated as required.
    /// - 1: THe buffer associated with this BD is empty, or reception is in progress.
    e: u1,
    /// Receive software ownership bit. Software use. This read/write bit is not
    /// modified by hardware and does not affect hardware.
    ro1: u1,
    /// Wrap, written by user
    /// - 0: The next BD is foudn in the consecutive location
    /// - 1: The next BD is foudn at the location defined in RAM.R_DES_START
    w: u1,
    /// Receive software ownership bit. Software use. This read/write but is not
    /// modified by hardware and does not affect hardware.
    ro2: u1,
    /// Last in frame, written by FEC
    /// - 0: The buffer is not the last in a frame
    /// - 1: the buffer is the last in a frame
    l: u1,
    /// Bits 5 and 6 are reserved
    reserved: u2,
    /// Miss, written by FEC, Set by the FEC for frames that were accepted in
    /// promiscuous mode but were flagged as a miss by the internal address recognition.
    /// Thus, while promiscuous mode is being used, the user can use the M bit to
    /// quickly determine whether the frame was destined to this station. This bit is
    /// valid only if both the L bit and PROM bit are set.
    /// - 0: the frame was received because of an address recognition bit
    /// - 1: the frame was received because of promiscuous mode
    m: u1,
    /// Set if the DA is broadcast
    bc: u1,
    /// Set if the DA is multicast and not broadcast
    mc: u1,
    /// Rx frame length violation, written by FEC. The frame length exceeds the
    /// value of MAX_FRAME_LENGTH in the bytes. The hardware truncates frames
    /// exceeding 2047 bytes so as not to overflow receive buffers.
    /// This bit is valid only if the L bit is set
    lg: u1,
    /// Rx nonoctet-aligned frame, written by FEC. A frame that contained a number
    /// of bits not divisible by 8 was received and the CRC check that occurred at
    /// the preceding byte boundary generated an error.
    /// This bit is valid only if the L bit is set. If this bit is set the CR bit is not.
    no: u1,
    /// Short frame, written by FEC. A frame length that was less than the minimum
    /// defined for this channel was recognized.
    sh: u1,
    /// Rx CRC error, written by FEC. This frame containes a CRC error and is an
    /// integral number of octects in length.
    /// This bit is valid only if the L bit is set.
    cr: u1,
    /// Overrun, written by FEC. A receive FIFO overrun ocurred during frame reception.
    /// If OV = 1, the other status bits, M, LG, NOm SH, CR, and CL lose their normal
    /// meaning and are cleared.
    /// This bit is valid only if the L bit is set.
    ov: u1,
    /// Truncate. Set if the receive frame is truncated (>= 2Kbytes)
    tr: u1,
}

#[bitsize(16)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct EthernetTxBufferDescriptorHeader {
    r: u1,
    to1: u1,
    w: u1,
    to2: u1,
    l: u1,
    tc: u1,
    def: u1,
    hb: u1,
    lc: u1,
    rl: u1,
    rc: u4,
    un: u1,
    csl: u1,
}

#[bitsize(16)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct IDMABufferDescriptorHeader {
    v: u1,
    reserved1: u1,
    w: u1,
    i: u1,
    l: u1,
    reserved2: u1,
    cm: u1,
    reserved8: u9,
}

#[bitsize(128)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct IDMABufferDescriptor {
    header: IDMABufferDescriptorHeader,
    dfcr: u8,
    sfcr: u8,
    buffer_length: u32,
    source_pointer: u32,
    dest_pointer: u32,
}

/// (Offset from IMMR, size, Name, Description, Manual Section)
#[allow(non_camel_case_types)]
type PRAM_DESC = (u64, u64, &'static str, &'static str, &'static str);
pub const FAST_ETHERNET_CONTROLLER_PRAM: &[PRAM_DESC] = &[
    (0xe00, 4, "ADDR_LOW", "Lower 32 Bits of Address", "44.4.1.1"),
    (
        0xe04,
        4,
        "ADDR_HIGH",
        "Upper 16 bits of address",
        "44.4.1.2",
    ),
    (
        0xe08,
        4,
        "HASH_TABLE_HIGH",
        "Upper 32 bits of hash table",
        "44.4.1.3",
    ),
    (
        0xe0c,
        4,
        "HASH_TABLE_LOW",
        "Lower 32 bits of hash table",
        "44.4.1.4",
    ),
    (
        0xe10,
        4,
        "R_DES_START",
        "Pointer to beginning of RxBD ring",
        "44.4.1.5",
    ),
    (
        0xe14,
        4,
        "X_DES_START",
        "Pointer to beginning of TxBD ring",
        "44.4.1.6",
    ),
    (0xe18, 2, "R_BUFF_SIZE", "Receive buffer size", "44.4.1.7"),
    (0xe40, 4, "ECNTRL", "Ethernet control register", "44.4.1.8"),
    (0xe44, 4, "IEVENT", "Interrupt event register", "44.4.1.9"),
    (0xe48, 4, "IMASK", "Interrupt mask register", "44.4.1.9"),
    (
        0xe4c,
        4,
        "IVEC",
        "Interrupt level and vector status",
        "44.4.1.10",
    ),
    (
        0xe50,
        4,
        "R_DES_ACTIVE",
        "Receive ring updated flag",
        "44.4.1.11",
    ),
    (
        0xe54,
        4,
        "X_DES_ACTIVE",
        "Transmit ring updated flag",
        "44.4.1.12",
    ),
    (0xe80, 4, "MII_DATA", "MII data register", "44.4.1.13"),
    (0xe84, 4, "MII_SPEED", "MII speed register", "44.4.1.14"),
    (
        0xecc,
        4,
        "R_BOUND",
        "End of FIFO_RAM (Read-Only)",
        "44.4.1.15",
    ),
    (
        0xed0,
        4,
        "R_FSTART",
        "Receive FIFO start address",
        "44.4.1.16",
    ),
    (0xee4, 4, "X_WMRK", "Transmit watermark", "44.4.1.17"),
    (
        0xeec,
        4,
        "X_FSTART",
        "Transmit FIFO start address",
        "44.4.1.18",
    ),
    (0xf34, 4, "FUN_CODE", "Function code to SDMA", "44.4.1.19"),
    (0xf48, 4, "R_HASH", "Receive hash register", "44.4.1.21"),
    (
        0xf84,
        4,
        "X_CNTRL",
        "Transmit control register",
        "44.4.1.22",
    ),
];

/// Parameter RAM map
/// | offset from IMMR | offset from DPRAM_BASE | Peripheral  |
/// |------------------|------------------------|-------------|
/// | 0x3c00           | 0x1c00                 | SCC1        |
/// | 0x3c80           | 0x1c80                 | i2c default |
/// | 0x3cb0           | 0x1cb0                 | misc        |
/// | 0x3cc0           | 0x1cc0                 | IDMA1       |
/// | 0x3d00           | 0x1d00                 | SCC2        |
/// | 0x3d80           | 0x1d80                 | SPI default |
/// | 0x3db0           | 0x1db0                 | RISC Timer  |
/// | 0x3dc0           | 0x1dc0                 | IDMA2       |
/// | 0x3e00           | 0x1e00                 | SCC2        |
/// | 0x3e80           | 0x1e80                 | SMC1        |
/// | 0x3ec0           | 0x1ec0                 | Reserved    |
/// | 0x3f00           | 0x1f00                 | SCC4        |
/// | 0x3f80           | 0x1f80                 | SMC2/PIP    |
/// | 0x3fc0           | 0x1fc0                 | Reserved    |
pub const PRAM_MAP: u64 = 0;

/// SPI + I2C
/// | Offset from DPRAM_BASE | bytes | peripheral |
/// |------------------------|-------|------------|
/// | 0x1c80                 | 44    | 12c default|
/// | 0x1cac                 | 2     | i2c_base   |
/// | 0x1cae                 | 2     | i2c default|
/// | 0x1d80                 | 44    | spi default|
/// | 0x1dac                 | 2     | spi_base   |
/// | 0x1dae                 | 2     | spi default|
pub const SPI_I2C_PRAM_RELOCATION: u64 = 0;

pub const RISC_TIMER_PRAM: &[PRAM_DESC] = &[
  (0x1db0, 2, "TM_BASE", "Timer table base address offset from DPRAM, reserve 4 bytes per timer used", "18.8.3"),
  (0x1db2, 2,"TM_PTR", "Timer table pointer, only used by CPM to point to next timer accessed in timer table", "18.8.3"),
  (0x1db4, 2,"R_TMR", "Timer mode register, used by CPM to store mode of timer (one shot 0 or restart 1)", "18.8.3"),
  (0x1db6, 2,"R_TMV", "Timer valid registr, used by the CP to determin whether a timer is enabled (bit is 1). Modified indirectly by `TM_CMD` and `SET_TIMER` opcode", "18.8.3"),
  (0x1db8, 4, "TM_CMD", "Used as a parameter location when `SET TIMER` opcode is issued. write to this location prior to opcode", "18.8.3.1"),
  (0x1dbc, 4,"TM_CNT", "TIck counter that CP updates after each tick or after table is scanned, tracks the number of ticks the CP responds to", "18.8.3.1"),
];

/// FIgure 19-7 IDMAx Channel's BD Table diagram shows the source + dest ring operations
const IDMA1_BASE_OFFSET: u64 = 0x3cc0;
const IDMA2_BASE_OFFSET: u64 = 0x3dc0;
pub const IDMA1PRAM: &[PRAM_DESC] = &[
  (IDMA1_BASE_OFFSET + 0x0, 2, "IBASE", "BD Base address, offset from the beginning of DPRAM, must be burst aligned (16)", "19.3.2"),
  (IDMA1_BASE_OFFSET + 0x2, 2, "DCMR", "DMA Channel mode register", "19.3.2"),
  (IDMA1_BASE_OFFSET + 0x4, 4, "SAPR", "Source data pointer, points to the next source bytes to be read, mutated by CPM", "19.3.2"),
  (IDMA1_BASE_OFFSET + 0x8, 4, "DAPR", "Destinatino data pointer, points to next destination byte to be writter, mutated by CPM", "19.3.2"),
  (IDMA1_BASE_OFFSET + 0xc, 2, "IBPTR", "Current IDMA BD Pointer (DPRAM offset), points to the next valid BD in the table, at reset of when end  (wrap bit of the BD trable is reached, the CPM wraps IBPTR back to IBASE)", "19.3.2"),
  (IDMA1_BASE_OFFSET + 0xe, 2, "WRITE_SP", "Internal use", "19.3.2"),
  (IDMA1_BASE_OFFSET + 0x10, 4, "S_BYTE_C", "Internal source byte count", "19.3.2"),
  (IDMA1_BASE_OFFSET + 0x14, 4, "D_BYTE_D", "Internal destination byte count", "19.3.2"),
  (IDMA1_BASE_OFFSET + 0x18, 4, "S_STATE", "Internal state", "19.3.2"),
  (IDMA1_BASE_OFFSET + 0x1c, 16, "ITEMP", "Temp data storage", "19.3.2"),
  (IDMA1_BASE_OFFSET + 0x2c, 4, "SR_MEM", "Data storage for peripheral write", "19.3.2"),
  (IDMA1_BASE_OFFSET + 0x30, 2, "READ_SP", "Internal use", "19.3.2"),
  (IDMA1_BASE_OFFSET + 0x32, 2, "Residue diff", "Difference between source and destination residue", "19.3.2"),
  (IDMA1_BASE_OFFSET + 0x34, 2, "Temp sotrage ptr", "Temp storage address pointer", "19.3.2"),
  (IDMA1_BASE_OFFSET + 0x36, 2, "SR_MEM_bytes", "SR_MEM byte count", "19.3.2"),
  (IDMA1_BASE_OFFSET + 0x38, 4, "D_STATE", "Reserved, internal state used by CPM", "19.3.2"),
];
pub const IDMA2PRAM: &[PRAM_DESC] = &[
  (IDMA2_BASE_OFFSET + 0x0, 2, "IBASE", "BD Base address, offset from the beginning of DPRAM, must be burst aligned (16)", "19.3.2"),
  (IDMA2_BASE_OFFSET + 0x2, 2, "DCMR", "DMA Channel mode register", "19.3.2"),
  (IDMA2_BASE_OFFSET + 0x4, 4, "SAPR", "Source data pointer, points to the next source bytes to be read, mutated by CPM", "19.3.2"),
  (IDMA2_BASE_OFFSET + 0x8, 4, "DAPR", "Destinatino data pointer, points to next destination byte to be writter, mutated by CPM", "19.3.2"),
  (IDMA2_BASE_OFFSET + 0xc, 2, "IBPTR", "Current IDMA BD Pointer (DPRAM offset), points to the next valid BD in the table, at reset of when end  (wrap bit of the BD trable is reached, the CPM wraps IBPTR back to IBASE)", "19.3.2"),
  (IDMA2_BASE_OFFSET + 0xe, 2, "WRITE_SP", "Internal use", "19.3.2"),
  (IDMA2_BASE_OFFSET + 0x10, 4, "S_BYTE_C", "Internal source byte count", "19.3.2"),
  (IDMA2_BASE_OFFSET + 0x14, 4, "D_BYTE_D", "Internal destination byte count", "19.3.2"),
  (IDMA2_BASE_OFFSET + 0x18, 4, "S_STATE", "Internal state", "19.3.2"),
  (IDMA2_BASE_OFFSET + 0x1c, 16, "ITEMP", "Temp data storage", "19.3.2"),
  (IDMA2_BASE_OFFSET + 0x2c, 4, "SR_MEM", "Data storage for peripheral write", "19.3.2"),
  (IDMA2_BASE_OFFSET + 0x30, 2, "READ_SP", "Internal use", "19.3.2"),
  (IDMA2_BASE_OFFSET + 0x32, 2, "Residue diff", "Difference between source and destination residue", "19.3.2"),
  (IDMA2_BASE_OFFSET + 0x34, 2, "Temp sotrage ptr", "Temp storage address pointer", "19.3.2"),
  (IDMA2_BASE_OFFSET + 0x36, 2, "SR_MEM_bytes", "SR_MEM byte count", "19.3.2"),
  (IDMA2_BASE_OFFSET + 0x38, 4, "D_STATE", "Reserved, internal state used by CPM", "19.3.2"),
];

pub const SCC1_BASE_OFFSET: u64 = 0x3c00;
pub const SCC2_BASE_OFFSET: u64 = 0x3d00;
pub const SCC3_BASE_OFFSET: u64 = 0x3e00;
pub const SCC4_BASE_OFFSET: u64 = 0x3f00;

#[bitsize(16)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct SccUartRxBufferDescriptorHeader {
    e: u1,
    reserved1: u1,
    w: u1,
    i: u1,
    c: u1,
    a: u1,
    cm: u1,
    id: u1,
    am: u1,
    reserved2: u1,
    br: u1,
    fr: u1,
    pr: u1,
    reserved3: u1,
    ov: u1,
    cd: u1,
}

#[bitsize(64)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct SccUartRxBufferDescriptor {
    header: SccUartRxBufferDescriptorHeader,
    data_length: u16,
    buffer_pointer: u32,
}

#[bitsize(16)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct SccUartTxBufferDescriptorHeader {
    r: u1,
    reserved1: u1,
    w: u1,
    i: u1,
    cr: u1,
    a: u1,
    cm: u1,
    p: u1,
    ns: u1,
    reserved2: u6,
    ct: u1,
}

#[bitsize(64)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct SccUartTxBufferDescriptor {
    header: SccUartTxBufferDescriptorHeader,
    data_length: u16,
    buffer_pointer: u32,
}

/// Starts from SCCxPRAM offset 0x30
pub const SCC_ETHERNET_PRAM: &[PRAM_DESC] = &[
    (0x0, 4, "C_PREC", "Preset CRC. for 32bit CRC-CCITT, initialize to 0xFFFF_FFFF", "27.8"),
    (0x4, 4, "C_MASK", "Constant mask for CRC. For the 32bit CTC-CCITT, initialized to 0xDEBB_20e3", "27.8"),
    (0x8, 4, "CRCEC", "CRC error counter maintained by the CPM", "27.8"),
    (0xc, 4, "ALEC", "Alignment error counter maintained by the CPM", "27.8"),
    (0x10, 4, "DISFC", "Discard frame error counter maintained by the CPM", "27.8"),
    (0x14, 2, "PADS", "Short frame PAD character. Write the pad character pattern to be sent when short frame padding is implemented into PADS. The pattern may be of any value, but both the highg and low bytes should be the same.", "27.8"),
    (0x16, 2, "RET_LIM", "Retry limit. Number of retries (typically 15 decimal) that can be made to send a frame. An interrupt can be generated if the limit is reached", "27.8"),
    (0x18, 2, "RET_CNT", "Retry Limit Counter, down count", "27.8"),
    (0x1a, 2, "MFLR", "Maximum frame length register (typically 1518 decimal). Ethernet controller checks legnth of incoming frames against this limit. Discard remainder of the frame and sets LG. MFLR == all-in frame bytes between the start frame delimiter and the end of the frame", "27.8"),
    (0x1c, 2, "MINFLR", "Minimum frame length register. the ethernet controller checks the length of the incoming frame against this register. discards bad frames. For transmitting, the controller pads the frame to make it at least MINFLR bytes long depending on the PAD value in the PRAM  / TxBD", "27.8"),
    (0x1e, 2, "MAXD1", "Maximum DMA1 length. Gives the option to stop sysbus writes after a frame exceeds a certain size. usually 1520 decimal.", "27.8"),
    (0x20, 2, "MAXD2", "Maximum DMA2 length. Gives the option to stop sysbus writes after a frame exceeds a certain size. usually 1520 decimal.", "27.8"),
    (0x22, 2, "MAXD", "Rx max DMA", "27.8"),
    (0x24, 2, "DMA_CNT", "Rx DMA coutner. temporary down-counter used to track frame legnth", "27.8"),
    (0x26, 2, "MAX_B", "MAximum BD byte count", "27.8"),
    (0x28, 2, "GADDR1", "Group address filter 1. Used in the hash table function of the group addressing mode.", "27.8"),
    (0x2a, 2, "GADDR2", "Group address filter 2. Used in the hash table function of the group addressing mode.", "27.8"),
    (0x2c, 2, "GADDR3", "Group address filter 3. Used in the hash table function of the group addressing mode.", "27.8"),
    (0x2e, 2, "GADDR4", "Group address filter 4. Used in the hash table function of the group addressing mode.", "27.8"),
    (0x30, 4, "TBUF0_DATA0", "Save area 0 -- current frame", "27.8"),
    (0x34, 4, "TBUF1_DATA1", "Save area 1 -- current frame", "27.8"),
    (0x38, 4, "TBUF0_RBA0", "", "27.8"),
    (0x3c, 4, "TBUF1_CRC", "", "27.8"),
    (0x40, 2, "TBUF0_BCNT", "", "27.8"),
    (0x42, 2, "PADDR1_H", "PADDR1 is the 48 bit individual address of this station", "27.8"),
    (0x44, 2, "PADDR1_M", "PADDR1 is the 48 bit individual address of this station", "27.8"),
    (0x46, 2, "PADDR1_L", "PADDR1 is the 48 bit individual address of this station", "27.8"),
    (0x48, 2, "P_PER", "Persistence, determines backoff behavior", "27.8"),
    (0x4a, 2, "RFBD_PTR", "Rx first BD PTR", "27.8"),
    (0x4c, 2, "TFBD_PTR", "Tx first BD PTR", "27.8"),
    (0x4e, 2, "TLBD_PTR", "Tx last BD PTR", "27.8"),
    (0x50, 4, "TBUF1_DATA0", "Save area 0 -- next frame", "27.8"),
    (0x54, 4, "TBUF1_DATA1", "Save area 1 -- next frame", "27.8"),
    (0x58, 4, "TBUF1_RBA0", "", "27.8"),
    (0x5c, 4, "TBUF1_CRC", "", "27.8"),
    (0x60, 2, "TBUF1_BCNT", "", "27.8"),
    (0x62, 2, "TX_LEN", "Tx frame length counter", "27.8"),
    (0x64, 2, "IADDR1", "Individual address filter 1-4, used in hash table function of the individual addressing mode.", "27.8"),
    (0x66, 2, "IADDR2", "Individual address filter 1-4, used in hash table function of the individual addressing mode.", "27.8"),
    (0x68, 2, "IADDR3", "Individual address filter 1-4, used in hash table function of the individual addressing mode.", "27.8"),
    (0x6a, 2, "IADDR4", "Individual address filter 1-4, used in hash table function of the individual addressing mode.", "27.8"),
    (0x6c, 2, "BOFF_CNT", "Backoff counter", "27.8"),
    (0x6e, 2, "TADDR_H", "Allows addition and deletion of addresses from individual and group hash tables. After placing an address in `TADDR`, issue `SET GROUP` opcode", "27.8"),
    (0x70, 2, "TADDR_M", "Allows addition and deletion of addresses from individual and group hash tables. After placing an address in `TADDR`, issue `SET GROUP` opcode", "27.8"),
    (0x72, 2, "TADDR_L", "Allows addition and deletion of addresses from individual and group hash tables. After placing an address in `TADDR`, issue `SET GROUP` opcode", "27.8"),
];

#[bitsize(16)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct SccEthernetRxBufferDescriptorHeader {
    e: u1,
    reserved1: u1,
    w: u1,
    i: u1,
    l: u1,
    f: u1,
    reserved2: u1,
    m: u1,
    resreved3: u2,
    lg: u1,
    no: u1,
    sh: u1,
    cr: u1,
    ov: u1,
    cl: u1,
}

#[bitsize(64)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct SccEthernetRxBufferDescriptor {
    header: SccEthernetRxBufferDescriptorHeader,
    data_length: u16,
    buffer_pointer: u32,
}

#[bitsize(16)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct SccEthernetTxBufferDescriptorHeader {
    r: u1,
    pad: u1,
    w: u1,
    i: u1,
    l: u1,
    tc: u1,
    def: u1,
    hb: u1,
    lc: u1,
    rl: u1,
    rc: u4,
    un: u1,
    csl: u1,
}

#[bitsize(64)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct SccEthernetTxBufferDescriptor {
    header: SccEthernetTxBufferDescriptorHeader,
    data_length: u16,
    buffer_pointer: u32,
}

pub const SCC1_PRAM: &[PRAM_DESC] = &[
    (0x0, 2, "RBASE", "RxBD Base offset from DPRAM, multiple of eight", "21.4"),
    (0x2, 2, "TBASE", "TxBD Base offset from DPRAM, multiple of eight", "21.4"),
    (0x4, 1, "RFCR", "Rx function Code", "21.4.1"),
    (0x5, 1, "TFCR", "Tx function COde", "21.4.1"),
    (0x6, 2, "MRBLR", "Maximum receive buffer length. number of bytes CPM can write in this buffer, must be multiple of 4 for ethernet and HDLC modes, and transparent mode.", "21.4"),
    (0x8, 4, "RSTATE", "Rx internal state", "21.4"),
    (0xc, 4, "RIP", "Rx internal buffer pointer, updated by SDMA channels to show the next address in the buffer to be accessed", "21.4"),
    (0x10, 2, "RBPTR", "Current RxBD pointer, points to the current BD being accessed or the next BD the receiver uses when idling. After reset of the end of the BD table is reached, CPM initialized RBPTR to value in RBASE.", "21.4"),
    (0x12, 2, "RCOUNT", "Rx internal byte count, a downcount value initialized with MRBLR and decremented with each byte written by the SDMA channel", "21.4"),
    (0x14, 4, "RTEMP", "Rx temp", "21.4"),
    (0x18, 4, "TSTATE", "Tx internal state", "21.4"),
    (0x1c, 4, "TIP", "Tx internal buffer pointer, the internal buffer pointers are updated by the SMA channels to show the next address in the buffer to be accessed" , "21.4"),
    (0x20, 2, "TBPTR", "CUrrent TxBD pointer, points to the current BD being processed or to the next BD the transmitter uses when it is idling. after Reset of end of the BD table is reached, the CPM initializes the TBPTR to the value in TBASE.", "21.4"),
    (0x22, 2, "TCOUNT", "Tx internal byte count, a downcount initialized with TxBD[DataLength] and decremented with each byte read by the supporting SDMA channel","21.4"
    ),
    (0x24, 4, "TTEMP", "Tx temp", "21.4"),
    (0x28, 4, "RCRC", "temp receive CRC", "21.4"),
    (0x2c, 4, "TCRC", "temp transmit CRC", "21.4"),
    // offset 0x30 is protocol specific
];

/// starts @ offset 0x30 from SCC1 PRAM "protocol specific"
pub const SCC_UART_PRAM: &[PRAM_DESC] = &[
  (0x0, 8, "reserved", "reserved", "22.4"),
  (0x8, 2, "MAX_IDL", "Maximum idle characters to receive before closing buffer and generate idl timeout interrupt for core to retreive data from the buffer. Bit length of idle character == 1 + data length (5-9) + 1 (if parity) + # of stop bits. Eg 8 data bits, no parity, 1 stop bit == 10 bits", "22.4"),
  (0xa, 2, "IDLC", "Tecmporary idle counter, holds the current idle count for the idle timeout process, downcounter", "22.4"),
  (0xc, 2, "BRKCR", "Break count register (transmit). Determines the number of break characters the transmitter sends. Sent when a `STOP TRANSMIT` opcode is issued. break character size is same math as IDLC", "22.4"),
  (0xe, 2, "PAREC", "User initialized counter of parity errors", "22.4"),
  (0x10, 2, "FRMEC", "User initialized counter of framing errors", "22.4"),
  (0x12, 2, "NOSEC", "User initialized counter of noise errors", "22.4"),
  (0x14, 2, "BRKEC", "User initialized counter of break conditions, once per signal", "22.4"),
  (0x16, 2, "BRKLN", "Last received break length measured in character units", "22.4"),
  (0x18, 2, "UADDR1", "UART address character 1/2. In multdrop mode, the receiver provides automatic address recognition for two addresses.", "22.4"),
  (0x1a, 2, "UADDR2", "UART address character 1/2. In multdrop mode, the receiver provides automatic address recognition for two addresses.", "22.4"),
  (0x1c, 2, "RTEMP", "Temporary storage", "22.4"),
  (0x1e, 2, "TOSEQ", "Transmit out of sequence character without affecting a Tx buffer in progress", "22.11"),
  (0x20, 2, "CHARACTER1", "Control character 1, define the Rx control character on which an interrupt can be generated", "22.4"),
  (0x22, 2, "CHARACTER2", "Control character 2, define the Rx control character on which an interrupt can be generated", "22.4"),
  (0x24, 2, "CHARACTER3", "Control character 3, define the Rx control character on which an interrupt can be generated", "22.4"),
  (0x26, 2, "CHARACTER4", "Control character 4, define the Rx control character on which an interrupt can be generated", "22.4"),
  (0x28, 2, "CHARACTER5", "Control character 5, define the Rx control character on which an interrupt can be generated", "22.4"),
  (0x2a, 2, "CHARACTER6", "Control character 6, define the Rx control character on which an interrupt can be generated", "22.4"),
  (0x2c, 2, "CHARACTER7", "Control character 7, define the Rx control character on which an interrupt can be generated", "22.4"),
  (0x2e, 2, "CHARACTER8", "Control character 8, define the Rx control character on which an interrupt can be generated", "22.4"),
  (0x30, 2, "RCCM", "Receive control character mask. Used to mask comparison of CHARACTER1-8 so classes of control characters can be defined. A 1 enabled comparison, a 0 masks it", "22.4"),
  (0x32, 2, "RCCR", "Receive control character register, used to hold the last rejected control hcaracter (not written to the Rx buffer), generates a maskable interrupt", "22.4"),
  (0x34, 2, "RLBC", "Receive last break character, used in synchronous UART, holds the last break character pattern.", "22.4"),
];

pub const SMC1_BASE_OFFSET: u64 = 0x3e80;
pub const SMC2_BASE_OFFSET: u64 = 0x3f80;

pub const SMC1_PRAM: &[PRAM_DESC] = &[
  (SMC1_BASE_OFFSET + 0x0, 2, "RBASE", "RxBD Base Address, should be multiple of eight", "29.2.3"),
  (SMC1_BASE_OFFSET + 0x2, 2, "TBASE", "TxBD Base Address, should be multiple of eight", "29.2.3"),
  (SMC1_BASE_OFFSET + 0x4, 1, "RFCR", "Rx function code", "29.2.3.1"),
  (SMC1_BASE_OFFSET + 0x5, 1, "TFCR", "Tx function code", "29.2.3.1"),
  (SMC1_BASE_OFFSET + 0x6, 2, "MRBLR", "Maximum receive buffer length", "29.2.3"),
  (SMC1_BASE_OFFSET + 0x8, 4, "RSTATE", "Rx internal state. Can only be used by the CPM", "29.2.3"),
  (SMC1_BASE_OFFSET + 0xc, 4, "RxDP", "Rx internal data pointer. Updated by SDMA channels to show the next address in the buffer to be accessed", "29.2.3"),
  (SMC1_BASE_OFFSET + 0x10, 2, "RBPTR", "RxBD pointer, points to the next BD for each SMC channel that the receiver tarnsfers fata to when it is in idle state, or to the current BD during frame processing. After reset of thwne the end of the table is reached, the CPM initializes RBPTR to RBASE.", "29.2.3"),
  (SMC1_BASE_OFFSET + 0x12, 2, "RxBC", "Rx internal byte count, count down value initialized with MRBLR and decremented with every write performed by the SDMA channel", "29.2.3"),
  (SMC1_BASE_OFFSET + 0x14, 4, "RxTEMP", "Rx temp, can only be used by the CPM", "29.2.3"),
  (SMC1_BASE_OFFSET + 0x18, 4, "TSTATE", "Tx internal state. can only be used by the CPM", "29.2.3"),
  (SMC1_BASE_OFFSET + 0x1c, 4, "TxDP", "Tx internal data pointer, updated by the SDMA channels to show the next address in the buffer to be accessed", "29.2.3"),
  (SMC1_BASE_OFFSET + 0x20, 2, "TBPTR", "TxBD poitner, points to the next BD for each SMC channel the transmitter transfers data from when in an idle state, or the current BD when active. on reset or BD table wraparound is initialized by CPM to TBPTR.", "29.2.3"),
  (SMC1_BASE_OFFSET + 0x22, 2, "TxBC", "Tx internal byte count, count down value initialized with the Tx BD data length and decremented with every byte the SDMA channels read", "29.2.3"),
  (SMC1_BASE_OFFSET + 0x24, 4, "TxTEMP", "Tx temp, can only be used by the CPM", "29.2.3"),
  (SMC1_BASE_OFFSET + 0x28, 2, "PS1", "First half word of protocol specific area", "29.2.3"),
  (SMC1_BASE_OFFSET + 0x32, 2, "PS2", "Last half worf of protocol specific area", "29.2.3"),
];

pub const SMC2_PRAM: &[PRAM_DESC] = &[
  (SMC2_BASE_OFFSET + 0x0, 2, "RBASE", "RxBD Base Address, should be multiple of eight", "29.2.3"),
  (SMC2_BASE_OFFSET + 0x2, 2, "TBASE", "TxBD Base Address, should be multiple of eight", "29.2.3"),
  (SMC2_BASE_OFFSET + 0x4, 1, "RFCR", "Rx function code", "29.2.3.1"),
  (SMC2_BASE_OFFSET + 0x5, 1, "TFCR", "Tx function code", "29.2.3.1"),
  (SMC2_BASE_OFFSET + 0x6, 2, "MRBLR", "Maximum receive buffer length", "29.2.3"),
  (SMC2_BASE_OFFSET + 0x8, 4, "RSTATE", "Rx internal state. Can only be used by the CPM", "29.2.3"),
  (SMC2_BASE_OFFSET + 0xc, 4, "RxDP", "Rx internal data pointer. Updated by SDMA channels to show the next address in the buffer to be accessed", "29.2.3"),
  (SMC2_BASE_OFFSET + 0x10, 2, "RBPTR", "RxBD pointer, points to the next BD for each SMC channel that the receiver tarnsfers fata to when it is in idle state, or to the current BD during frame processing. After reset of thwne the end of the table is reached, the CPM initializes RBPTR to RBASE.", "29.2.3"),
  (SMC2_BASE_OFFSET + 0x12, 2, "RxBC", "Rx internal byte count, count down value initialized with MRBLR and decremented with every write performed by the SDMA channel", "29.2.3"),
  (SMC2_BASE_OFFSET + 0x14, 4, "RxTEMP", "Rx temp, can only be used by the CPM", "29.2.3"),
  (SMC2_BASE_OFFSET + 0x18, 4, "TSTATE", "Tx internal state. can only be used by the CPM", "29.2.3"),
  (SMC2_BASE_OFFSET + 0x1c, 4, "TxDP", "Tx internal data pointer, updated by the SDMA channels to show the next address in the buffer to be accessed", "29.2.3"),
  (SMC2_BASE_OFFSET + 0x20, 2, "TBPTR", "TxBD poitner, points to the next BD for each SMC channel the transmitter transfers data from when in an idle state, or the current BD when active. on reset or BD table wraparound is initialized by CPM to TBPTR.", "29.2.3"),
  (SMC2_BASE_OFFSET + 0x22, 2, "TxBC", "Tx internal byte count, count down value initialized with the Tx BD data length and decremented with every byte the SDMA channels read", "29.2.3"),
  (SMC2_BASE_OFFSET + 0x24, 4, "TxTEMP", "Tx temp, can only be used by the CPM", "29.2.3"),
  // Keeping these in case they are needed, but they seem to be mostly
  // included as markers in the specification
  //
  // (SMC2_BASE_OFFSET + 0x28, 2, "PS1", "First half word of protocol specific area", "29.2.3"),
  // (SMC2_BASE_OFFSET + 0x32, 2, "PS2", "Last half word of protocol specific area", "29.2.3"),
];

// TODO: Serial Management Controller UART PRAM
/// SMC UART PRAM is relative to the protocol specific area (SMC_BASE + 0x28 bytes)
pub const SCM_UART_PRAM: &[PRAM_DESC] = &[
    (0x0, 2, "MAX_IDL", "Maximum idle characters", "29.3.2"),
    (
        0x2,
        2,
        "IDLC",
        "Temporary IDLE counter. down counter the CPM stores the current idle counter",
        "29.3.2",
    ),
    (
        0x4,
        2,
        "BRKLN",
        "Last received break length, accurate w/in one character length",
        "29.3.2",
    ),
    (0x6, 2, "BRKEC", "Receive break condition counter", "29.3.2"),
    (0x8, 2, "BRKCR", "Break count register (transmit)", "29.3.2"),
    (0xa, 2, "R_MASK", "Temporary bit mask", "29.3.2"),
];

#[bitsize(16)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct SmcUartRxBufferDescriptorHeader {
    e: u1,
    reserved1: u1,
    w: u1,
    i: u1,
    reserved2: u2,
    cm: u1,
    id: u1,
    reserved3: u2,
    br: u1,
    fr: u1,
    pr: u1,
    reserved4: u1,
    ov: u1,
    reserved5: u1,
}

#[bitsize(64)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct SmcUartRxBufferDescriptor {
    header: SmcUartRxBufferDescriptorHeader,
    data_length: u16,
    buffer_pointer: u32,
}

#[bitsize(16)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct SmcUartTxBufferDescriptorHeader {
    r: u1,
    reserved1: u1,
    w: u1,
    i: u1,
    reserved2: u2,
    cm: u1,
    p: u1,
    reserved3: u8,
}

#[bitsize(64)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct SmcUartTxBufferDescriptor {
    header: SmcUartTxBufferDescriptorHeader,
    data_length: u16,
    buffer_pointer: u32,
}

pub const SPI_PRAM_BASE: u64 = 0x3d80;
pub const SPI_PRAM: &[PRAM_DESC] = &[
  (SPI_PRAM_BASE + 0x0, 2, "RBASE", "RxBD table base address", "30.5"),
  (SPI_PRAM_BASE + 0x2, 2, "TBASE", "TxBD table base address", "30.5"),
  (SPI_PRAM_BASE + 0x4, 1, "RFCR", "Rx function code, contains the value to appear on AT[1-2] when the asociated SDMA channel accesses memory", "30.5.1"),
  (SPI_PRAM_BASE + 0x5, 1, "TFCR", "Tx function code, contains the value to appear on AT[1-2] when the asociated SDMA channel accesses memory", "30.5.1"),
  (SPI_PRAM_BASE + 0x6, 2, "MRBLR", "Maximum receive buffer length", "30.5"),
  (SPI_PRAM_BASE + 0x8, 4, "RSTATE", "Rx internal state", "30.5"),
  (SPI_PRAM_BASE + 0xc, 4, "RxDP", "Rx internal data pointer", "30.5"),
  (SPI_PRAM_BASE + 0x10, 2, "RBPTR", "RxBD pointer", "30.5"),
  (SPI_PRAM_BASE + 0x12, 2, "RxBC", "Rx internal byte count", "30.5"),
  (SPI_PRAM_BASE + 0x14, 4, "RxTEMP", "Rx temp", "30.5"),
  (SPI_PRAM_BASE + 0x18, 4, "TSTATE", "Tx internal state", "30.5"),
  (SPI_PRAM_BASE + 0x1c, 4, "TxDP", "Tx internal data pointer", "30.5"),
  (SPI_PRAM_BASE + 0x20, 2, "TBPTR", "TxBD pointer", "30.5"),
  (SPI_PRAM_BASE + 0x22, 2, "TxBC", "Tx internal byte count", "30.5"),
  (SPI_PRAM_BASE + 0x24, 4, "TxTEMP", "Tx internal temp", "30.5"),
  (SPI_PRAM_BASE + 0x28, 8, "RELOC", "used during i2c/spi relocation", "18.7.3"),
];

#[bitsize(16)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct SpiRxBufferDescriptorHeader {
    e: u1,
    reserved1: u1,
    w: u1,
    i: u1,
    l: u1,
    reserved2: u1,
    cm: u1,
    reserved3: u7,
    ov: u1,
    me: u1,
}

#[bitsize(64)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct SpiRxBufferDescriptor {
    header: SpiRxBufferDescriptorHeader,
    data_length: u16,
    buffer_pointer: u32,
}

#[bitsize(16)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct SpiTxBufferDescriptorHeader {
    r: u1,
    reserved1: u1,
    w: u1,
    i: u1,
    l: u1,
    reserved2: u1,
    cm: u1,
    reserved3: u7,
    un: u1,
    me: u1,
}

#[bitsize(64)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct SpiTxBufferDescriptor {
    header: SpiTxBufferDescriptorHeader,
    data_length: u16,
    buffer_pointer: u32,
}

pub const I2C_PRAM_BASE: u64 = 0x3c80;
pub const I2C_PRAM: &[PRAM_DESC] = &[
    (
        I2C_PRAM_BASE + 0x0,
        2,
        "RBASE",
        "RxBD table base address",
        "31.5",
    ),
    (
        I2C_PRAM_BASE + 0x2,
        2,
        "TBASE",
        "TxBD table base address",
        "31.5",
    ),
    (
        I2C_PRAM_BASE + 0x4,
        1,
        "RFCR",
        "Rx function code",
        "figure 31.11 and table 31.7",
    ),
    (
        I2C_PRAM_BASE + 0x5,
        1,
        "TFCR",
        "Tx function code",
        "figure 31.11 and table 31.7",
    ),
    (
        I2C_PRAM_BASE + 0x6,
        2,
        "MRBLR",
        "Maximum receive buffer length",
        "31.5",
    ),
    (
        I2C_PRAM_BASE + 0x8,
        4,
        "RSTATE",
        "Rx internal state",
        "31.5",
    ),
    (
        I2C_PRAM_BASE + 0xc,
        4,
        "RxDP",
        "Rx internal data pointer",
        "31.5",
    ),
    (I2C_PRAM_BASE + 0x10, 2, "RBPTR", "RxBD pointer", "31.5"),
    (
        I2C_PRAM_BASE + 0x12,
        2,
        "RxBC",
        "Rx internal byte count",
        "31.5",
    ),
    (I2C_PRAM_BASE + 0x14, 4, "RxTEMP", "Rx temp", "31.5"),
    (
        I2C_PRAM_BASE + 0x18,
        4,
        "TSTATE",
        "Tx internal state",
        "31.5",
    ),
    (
        I2C_PRAM_BASE + 0x1c,
        4,
        "TxDP",
        "Tx internal data pointer",
        "31.5",
    ),
    (I2C_PRAM_BASE + 0x20, 2, "TBPTR", "TxBD pointer", "31.5"),
    (
        I2C_PRAM_BASE + 0x22,
        2,
        "TxBC",
        "Tx internal byte count",
        "31.5",
    ),
    (
        I2C_PRAM_BASE + 0x24,
        4,
        "TxTEMP",
        "Tx internal temp",
        "31.5",
    ),
    (
        I2C_PRAM_BASE + 0x28,
        8,
        "RELOC",
        "used during i2c/spi relocation",
        "18.7.3",
    ),
];

#[bitsize(16)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct I2CRxBufferDescriptorHeader {
    e: u1,
    reserved1: u1,
    w: u1,
    i: u1,
    l: u1,
    reserved2: u9,
    ov: u1,
    reserved3: u1,
}

#[bitsize(64)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct I2CRxBufferDescriptor {
    header: I2CRxBufferDescriptorHeader,
    data_length: u16,
    buffer_pointer: u32,
}

#[bitsize(16)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct I2CTxBufferDescriptorHeader {
    r: u1,
    reserved1: u1,
    w: u1,
    i: u1,
    l: u1,
    s: u1,
    reserved2: u7,
    nak: u1,
    un: u1,
    cl: u1,
}

#[bitsize(64)]
#[derive(DebugBits, FromBits, PartialEq, Eq, Clone)]
pub struct I2CTxBufferDescriptor {
    header: I2CTxBufferDescriptorHeader,
    data_length: u16,
    buffer_pointer: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn no_overlap() {
        let mut registers = IMMR_REGISTERS.to_vec();
        registers.sort_unstable();
        let registers = registers;
        let len = registers.len();

        // len - 1 since there is nothing to compare the last index against,
        // also makes the logic easier
        for i in 0..(len - 1) {
            let current = &registers[i];
            let current_base = current.offset();
            let current_end = current_base + current.byte_size();
            for comparee in registers.iter().take(len).skip(i + 1) {
                // make sure that the registers do not overlap
                assert!(
                    comparee.offset > current_base,
                    "IMMR reg `{}` starts before reg `{}` starts!",
                    comparee.abbreviation(),
                    current.abbreviation()
                );
                assert!(
                    comparee.offset >= current_end,
                    "IMMR reg `{}` starts before reg `{}` ends!",
                    comparee.abbreviation(),
                    current.abbreviation()
                );
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn no_end_overlap() {
        let mut registers = IMMR_REGISTERS.to_vec();
        registers.sort_unstable();
        let registers = registers;
        let len = registers.len();

        // len - 1 since there is nothing to compare the last index against,
        // also makes the logic easier
        for i in 0..(len - 1) {
            let current = &registers[i];
            let current_base = current.offset();
            let current_end = current.end();
            for comparee in registers.iter().take(len).skip(i + 1) {
                // make sure that the registers do not overlap
                assert!(
                    comparee.offset > current_base,
                    "IMMR reg `{}` starts before reg `{}` starts!",
                    comparee.abbreviation(),
                    current.abbreviation()
                );
                assert!(
                    comparee.offset > current_end,
                    "IMMR reg `{}` starts before reg `{}` ends!",
                    comparee.abbreviation(),
                    current.abbreviation()
                );
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn no_gaps() {
        let mut registers = IMMR_REGISTERS.to_vec();
        registers.sort_unstable();
        let registers = registers;

        let first = registers.first().unwrap();
        let last = registers.last().unwrap();

        // range of all addresses in the region
        let range = first.offset()..(last.end());

        for i in range {
            assert!(
                region_contains(i, &registers),
                "IMMR offset `{0}` ({0:#x}) is not contained in a register",
                i
            );
        }

        fn region_contains(offset: u32, registers: &[&ImmrRegisterDescriptor]) -> bool {
            for reg in registers.iter() {
                if (reg.offset()..=reg.end()).contains(&offset) {
                    return true;
                }
            }

            false
        }
    }
}
