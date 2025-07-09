// SPDX-License-Identifier: BSD-2-Clause
use derivative::Derivative;
use styx_core::prelude::*;
use tracing::debug;

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Mcg;

// On a real device, changing clock modes or initialization requires waiting for reference sources to stabilize
// and for phase/frequency locks to be acquired.  We make these events instantaneous because we don't have a real clock.

// register addresses, all registers are 8 bits wide
// MCG_S is RO, everything else is RW
const MCG_BASE: u64 = 0x4006_4000;
const MCG_C1: u64 = MCG_BASE;
const MCG_C2: u64 = MCG_BASE + 0x1;
// PLL Clock Enable
const MCG_C5: u64 = MCG_BASE + 0x4;
// PLL Select
const MCG_C6: u64 = MCG_BASE + 0x5;
// status registers
const MCG_S: u64 = MCG_BASE + 0x6;
const MCG_SC: u64 = MCG_BASE + 0x8;
// MCG OSC Clock Select
const MCG_C7: u64 = MCG_BASE + 0xC;
// toggles interrupts for various loss-of-clock related things. not needed for emulation
const MCG_C8: u64 = MCG_BASE + 0xD;
// reserved registers, always zero
const MCG_C9: u64 = MCG_BASE + 0xE;
const MCG_C10: u64 = MCG_BASE + 0xF;

const CLKS_MASK: u8 = 0xC0;
const PLLCLKEN0: u8 = 1 << 6;
const PLL_LOCK0: u8 = 1 << 6;
const PLLS: u8 = 1 << 6;
const PLLST: u8 = 1 << 5;
const IREFS: u8 = 1 << 2;
const IREFST: u8 = 1 << 4;
const IRCS: u8 = 1;
const IRCST: u8 = 1;
const OSCINIT0: u8 = 1 << 1;
const CLKST: u8 = 0xc;
const IRCLKEN: u8 = 1 << 1;

/// helper function to read the mcg status register
#[inline]
fn read_status(mmu: &mut Mmu) -> u8 {
    mmu.read_u8_le_phys_code(MCG_S).unwrap()
}

fn mcg_w_hook(proc: CoreHandle, address: u64, _size: u32, data: &[u8]) -> Result<(), UnknownError> {
    let value = data[0];
    let mut status = read_status(proc.mmu);
    match address {
        MCG_C1 => {
            debug!("writing {:08b} to C1", value);
            if value & IREFS > 0 {
                status |= IREFST;
            } else {
                status &= !IREFST;
            }

            status &= !CLKST;

            match (value & CLKS_MASK) >> 6 {
                0x0 => {
                    if (status & PLLST) > 0 {
                        status |= 0xc;
                    }
                }
                0x1 => status |= 0x4,
                0x2 => status |= 0x8,
                _ => (),
            }

            if (value & IRCLKEN) > 0 {
                if (proc.mmu.read_u8_le_phys_code(MCG_C2).unwrap() & IRCS) > 0 {
                    status |= IRCST;
                } else {
                    status &= !IRCST;
                }
            }
        }
        MCG_C2 => {
            debug!("writing {:08b} to C2", value);
            if value & IRCS > 0 {
                status |= IRCST;
            } else {
                status &= !IRCST;
            }
        }
        MCG_C5 => {
            debug!("writing {:08b} to C5", value);
            if (value & PLLCLKEN0) > 0 {
                status |= PLL_LOCK0;
            } else {
                status &= !PLL_LOCK0;
            }
        }
        MCG_C6 => {
            debug!("writing {:08b} to C6", value);
            if (value & PLLS) > 0 {
                status |= PLLST | PLL_LOCK0;
            } else {
                status &= !(PLLST | PLL_LOCK0);
            }
        }
        _ => (),
    }
    debug!(
        "\tUpdated MCG_S: {:08b}, @0x{:x}",
        status,
        proc.cpu.pc().unwrap()
    );
    proc.mmu.write_data(MCG_S, &[status]).unwrap();
    Ok(())
}

const OSC_CR: u64 = 0x4006_5000;
const ERCLKEN: u8 = 1 << 7;

fn osc_cr_w_hook(
    proc: CoreHandle,
    address: u64,
    _size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    debug_assert!(address == OSC_CR);

    let value = data[0];

    if (value & ERCLKEN) > 0 {
        let s = read_status(proc.mmu);
        debug!(
            "Updated Status Register: {:08b}, @0x{:x}",
            s | OSCINIT0,
            proc.cpu.pc().unwrap()
        );
        proc.mmu.write_data(MCG_S, &[s | OSCINIT0]).unwrap();
    }

    Ok(())
}

impl Peripheral for Mcg {
    fn tick(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _event_controller: &mut dyn EventControllerImpl,
        _delta: &styx_core::executor::Delta,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        // register hooks
        proc.core
            .cpu
            .mem_write_hook(MCG_BASE, MCG_C10, Box::new(mcg_w_hook))?;
        proc.core
            .cpu
            .mem_write_hook(OSC_CR, OSC_CR, Box::new(osc_cr_w_hook))?;

        Ok(())
    }

    fn name(&self) -> &str {
        "MCG"
    }

    fn reset(&mut self, _cpu: &mut dyn CpuBackend, mmu: &mut Mmu) -> Result<(), UnknownError> {
        // Register reset values
        // C1  = 0x4
        // C2  = 0x80
        // C5  = 0x0
        // C6  = 0x0
        // S   = 0x10
        // SC  = 0x2
        // C7  = 0x0
        // C8  = 0x80
        // C9  = 0x0
        // C10 = 0x0
        // all others are undefined
        mmu.write_data(MCG_C1, &[0x4]).unwrap();
        mmu.write_data(MCG_C2, &[0x80]).unwrap();
        mmu.write_data(MCG_C5, &[0x0]).unwrap();
        mmu.write_data(MCG_C6, &[0x0]).unwrap();
        mmu.write_data(MCG_S, &[0x10]).unwrap();
        mmu.write_data(MCG_SC, &[0x2]).unwrap();
        mmu.write_data(MCG_C7, &[0x0]).unwrap();
        mmu.write_data(MCG_C8, &[0x80]).unwrap();
        mmu.write_data(MCG_C9, &[0x0]).unwrap();
        mmu.write_data(MCG_C10, &[0x0]).unwrap();

        Ok(())
    }
}
