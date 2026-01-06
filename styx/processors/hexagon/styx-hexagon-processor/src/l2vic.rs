// SPDX-License-Identifier: BSD-2-Clause

//! Hexagon l2vic interrupt controller.
//! See quic qemu's docs/devel/hexagon-l2vic.rst, hw/intc/l2vic.c and include/hw/intc/l2vic.h
//!
//! And Arm PrimeCell PL190 interrupt controller documentation.

use arbitrary_int::*;
use bitbybit::{bitenum, bitfield};
use styx_core::{
    cpu::CpuBackend,
    errors::UnknownError,
    event_controller::{ActivateIRQnError, InterruptExecuted, Peripherals},
    hooks::CoreHandle,
    memory::Mmu,
    prelude::{
        log::{error, trace},
        Context, EventControllerImpl, ExceptionNumber,
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

/// See QEMU's hw/intc/l2vic.c, specifically
/// fastl2vic_write, for more details.
#[derive(Debug)]
#[bitenum(u2)]
pub enum FastL2VicCommand {
    Enable = 0,
    Disable = 1,
    // Goes to soft int according to fastl2vic_write in
    // hw/intc/l2vic.c
    Interrupt = 2,
}

/// See QEMU's hw/intc/l2vic.c, specifically
/// fastl2vic_write, for more details.
#[bitfield(u32, debug)]
pub struct FastL2VicControl {
    #[bits(0..=9, r)]
    irq: u10,
    #[bits(16..=17, r)]
    command: Option<FastL2VicCommand>,
}

impl FastL2VicControl {
    /// Each IRQ for the l2vic belongs to a specific slice. This function gets the
    /// slice that the IRQ in the command corresponds to.
    ///
    /// The IRQs are split such that IRQs 0-31 are in slice 0,
    /// 32 to 63 are in slice 1, 64 to 95 are in slice 3, etc..
    pub fn slice(&self) -> usize {
        self.irq().as_usize() / 32
    }
}

/// Handle MMIO write to fastl2vic
/// register. See QEMU's hw/intc/l2vic.c
fn fastl2vic_mmio_write_hook(
    proc: CoreHandle,
    address: u64,
    size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let l2vic = proc.event_controller.get_impl::<L2Vic>()?;
    let fastl2vic_control = FastL2VicControl::new_with_raw_value(u32::from_le_bytes(
        data.try_into()
            .with_context(|| "couldn't convert fastl2vic access into u32")?,
    ));

    error!(
        "fastl2vic access address {address:x} {size:x} {data:x?} pc {:x?}, register {:x?}",
        proc.cpu.pc(),
        fastl2vic_control
    );

    match fastl2vic_control.command() {
        // According to QEMU this is EnableSet
        Ok(FastL2VicCommand::Enable) => {
            l2vic.handle_register_write(
                L2VicRegister::EnableSet,
                fastl2vic_control.slice(),
                fastl2vic_control.irq().as_u32(),
            )?;
        }
        _ => unimplemented!(),
    }

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
        "l2vic base writing at {address:x} and size {size:x} with data {data:x?}, pc is {:x?}",
        proc.cpu.pc()
    );

    match register {
        Ok(register) => {
            l2vic.handle_register_write(register, slot, data_u32)?;
        }
        Err(_) => todo!(),
    }

    Ok(())
}

#[derive(Default)]
pub struct L2Vic {
    slots: [L2VicSlot; L2VIC_NUM_SLOTS as usize],
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
    pending: u32,
}

impl L2VicSlot {
    pub fn irqn_enable(&self, n: usize) -> bool {
        ((self.enable >> n) & 1) == 1
    }
    pub fn irqn_clear(&self, n: usize) -> bool {
        ((self.clear >> n) & 1) == 1
    }
    pub fn irqn_int_type(&self, n: usize) -> bool {
        ((self.int_type >> n) & 1) == 1
    }
    pub fn irqn_pending(&self, n: usize) -> bool {
        ((self.pending >> n) & 1) == 1
    }
}

impl L2Vic {
    fn handle_register_write(
        &mut self,
        register: L2VicRegister,
        slot: usize,
        data: u32,
    ) -> Result<(), UnknownError> {
        error!("register {register:?} slot {slot} data {data:x}");

        match register {
            L2VicRegister::Enable => {
                self.slots[slot].enable = data;
            }
            // self_write in hw/intc/l2vic.c:
            // is similar to Enable, but sets the bits in data in the
            // current enabled field instead of overwriting the enable field with the bits.
            L2VicRegister::EnableSet => {
                self.slots[slot].enable |= data;
            }
            L2VicRegister::Type => {
                self.slots[slot].int_type = data;
            }
            L2VicRegister::Clear => {
                self.slots[slot].clear = data;
            }
            _ => todo!(),
        }

        self.process_changes()?;
        Ok(())
    }

    /// This should be called after the internal state of the
    /// L2vic is changed, such as after a register write.
    ///
    /// See l2vic_update_all and l2vic_update for more details
    /// in hw/intc/l2vic.c.
    pub fn process_changes(&mut self) -> Result<(), UnknownError> {
        // 1. Go through every IRQ and, then see if the IRQ is
        // enabled and pending. If it is, then indicate the interurpt
        // has been raised

        for slot in &self.slots {
            // Now go through the IRQs
            // As each slot is 32 bits, the IRQ is 32 bits
            for i in 0..32 {
                // This means the IRQ must be triggered.
                if slot.irqn_enabled(i) && slot.irqn_pending(i) {}
            }
        }

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
            FASTL2VIC_BASE + 0x4,
            Box::new(fastl2vic_mmio_write_hook),
        )?;

        Ok(())
    }
}
