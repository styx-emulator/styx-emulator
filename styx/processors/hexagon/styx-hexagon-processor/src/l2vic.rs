// SPDX-License-Identifier: BSD-2-Clause

//! Hexagon l2vic interrupt controller.
//! See quic qemu's docs/devel/hexagon-l2vic.rst, hw/intc/l2vic.c and include/hw/intc/l2vic.h
//!
//! And Arm PrimeCell PL190 interrupt controller documentation.

use bitbybit::bitenum;
use styx_core::{
    cpu::CpuBackend,
    errors::UnknownError,
    event_controller::{ActivateIRQnError, InterruptExecuted, Peripherals},
    hooks::CoreHandle,
    memory::Mmu,
    prelude::{
        anyhow,
        log::{error, trace},
        BuildingProcessor, Context, EventControllerImpl, ExceptionNumber, Peripheral,
    },
};

const SUBSYSTEM_BASE: u64 = 0xfc900000;

const L2VIC_BASE: u64 = SUBSYSTEM_BASE + L2VIC_OFFSET;
const L2VIC_OFFSET: u64 = 0x10000;
const L2VIC_NUM_SLOTS: u64 = 32;
const L2VIC_CONFIG_START: u64 = 0x100;

const FASTL2VIC_BASE: u64 = 0xd83e0000;

/// The l2vic can handle 32 interrupts.
/// Each of these interrupts are configured
/// through the reigsters below. Each register
/// is 32 contiguous 4-byte values that pertains
/// to each interrupt. So you would have
/// 128 bytes of enable, then 128 bytes of
/// EnableClear, etc.
///
/// PL190 2.1 "there are 32 interrupt lines."
///
/// From include/hw/intc/l2vic.h in QUIC QEMU.
/// The commented offsets are the offsets
/// used in QEMU to indicate the start of a register
/// (including all 32 interrupts). The start of the block is
/// 0x100 after the l2vic base, but we encode the enum
/// as zero-offset for clarity.
///
/// NOTE these comments might not make a lot of sense.
#[derive(Debug)]
#[bitenum(u16, exhaustive = false)]
pub enum L2VicRegister {
    // 0x100
    Enable = 0,
    // 0x180
    EnableClear = 1,
    // 0x200
    EnableSet = 2,
    // 0x280
    Type = 3,
    // 0x300
    Unknown0 = 4,
    // 0x380
    Status = 5,
    // 0x400
    Clear = 6,
    // 0x480
    Int = 7,
    // 0x500
    Pending = 8,
    // 0x580
    Unknown1 = 9,
    // 0x600
    GRP0 = 10,
    // 0x680
    GRP1 = 11,
    // 0x700
    GRP2 = 12,
    // 0x780
    GRP3 = 13,
}

#[bitenum(u8, exhaustive = false)]
pub enum FastL2VicBase {
    Enable = 0,
    Disable = 1,
    // Goes to soft int according to fastl2vic_write in
    // hw/intc/l2vic.c
    Interrupt = 2,
}

fn fastl2vic_mmio_write_hook(
    proc: CoreHandle,
    address: u64,
    size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    error!(
        "fastl2vic access address {address:x} {size:x} {data:x?} pc {:x?}",
        proc.cpu.pc()
    );

    Ok(())
}

fn l2vic_mmio_write_hook(
    proc: CoreHandle,
    address: u64,
    size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let l2vic = proc.event_controller.get_impl::<L2Vic>()?;

    // Compute the register that we are writing to and the interrupt number
    let register = L2VicRegister::new_with_raw_value(
        ((address - L2VIC_BASE - L2VIC_CONFIG_START) / (L2VIC_NUM_SLOTS * 4)) as u16,
    );

    // This finds the "offset" into the register array. Since each register value
    // is 4 bytes, we divide by four to get the actual interrupt number.
    let slot = (((address - L2VIC_BASE - L2VIC_CONFIG_START) % (L2VIC_NUM_SLOTS * 4)) / 4) as usize;

    // All the values are 32 bits, see QEMU l2vic.c and
    // L2VICState.
    let data_u32 = u32::from_le_bytes(
        data.try_into()
            .with_context(|| "couldn't get l2vic write as u32")?,
    );

    error!(
        "l2vic base writing at {address:x} and size {size:x} with data {data:x?}, register {register:?} interrupt {slot}, pc is {:x?}",
        proc.cpu.pc()
    );
    match register {
        Ok(L2VicRegister::Enable) => {
            l2vic.interrupts[slot].enable = data_u32;
        }
        Ok(L2VicRegister::Type) => {
            l2vic.interrupts[slot].int_type = data_u32;
        }
        Ok(L2VicRegister::Clear) => {
            l2vic.interrupts[slot].clear = data_u32;
        }
        _ => todo!(),
    }

    l2vic.reconfigure()?;

    Ok(())
}

#[derive(Default)]
pub struct L2Vic {
    interrupts: [L2VicSlot; L2VIC_NUM_SLOTS as usize],
}

/// QEMU mentions a lot about slices... what are these so-called slices?
/// In our case, it seems to just compute down to 32 interrupts.
#[derive(Default)]
pub struct L2VicSlot {
    // I think this is supposed to be 32 bits
    // where each bit represents the nth interrupt
    // for the nth slot.
    enable: u32,
    clear: u32,
    int_type: u32,
}

impl L2Vic {
    pub fn reconfigure(&mut self) -> Result<(), UnknownError> {
        Ok(())
    }
}

impl EventControllerImpl for L2Vic {
    fn next(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _peripherals: &mut Peripherals,
    ) -> Result<InterruptExecuted, UnknownError> {
        trace!("event controller next unimplemented");
        Ok(InterruptExecuted::NotExecuted)
    }

    fn latch(&mut self, _event: ExceptionNumber) -> Result<(), ActivateIRQnError> {
        todo!()
    }

    fn execute(
        &mut self,
        _irq: ExceptionNumber,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
    ) -> Result<InterruptExecuted, ActivateIRQnError> {
        todo!()
    }

    fn finish_interrupt(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
    ) -> Option<ExceptionNumber> {
        todo!()
    }

    fn init(&mut self, cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        trace!("the hexagon l2vic has started");
        cpu.mem_write_hook(
            L2VIC_BASE,
            L2VIC_BASE + 0x1000,
            Box::new(l2vic_mmio_write_hook),
        )?;

        cpu.mem_write_hook(
            FASTL2VIC_BASE,
            FASTL2VIC_BASE + 0x1000,
            Box::new(fastl2vic_mmio_write_hook),
        )?;

        Ok(())
    }
}
