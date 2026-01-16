// SPDX-License-Identifier: BSD-2-Clause

//! Hexagon l2vic interrupt controller.
//! See quic qemu's docs/devel/hexagon-l2vic.rst, hw/intc/l2vic.c and include/hw/intc/l2vic.h
//!
//! And Arm PrimeCell PL190 interrupt controller documentation.
//!
//! It appears that the l2vic (QEMU) describes that
//! all interrupts go to VID 0, which is IRQ 2.

use arbitrary_int::*;
use bitbybit::{bitenum, bitfield};
use styx_core::{
    arch::hexagon::{register_fields::Ssr, HexagonRegister},
    cpu::{CpuBackend, CpuBackendExt, HexagonInterruptType},
    errors::UnknownError,
    event_controller::{ActivateIRQnError, InterruptExecuted, Peripherals},
    hooks::CoreHandle,
    memory::Mmu,
    prelude::{
        log::{error, info, trace},
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

    // See fastl2vic_write
    match fastl2vic_control.command() {
        // According to QEMU this is EnableSet
        Ok(FastL2VicCommand::Enable) => {
            l2vic.handle_register_write(
                L2VicRegister::EnableSet,
                fastl2vic_control.slice(),
                fastl2vic_control.irq().as_u32(),
            )?;
        }
        // According to QEMU this is EnableClear
        Ok(FastL2VicCommand::Disable) => {
            l2vic.handle_register_write(
                L2VicRegister::EnableClear,
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
    vid: u32,
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
    // 1 = edge triggered
    // 0 = level triggered
    // See fastint.c in qemu-hexagon-testing for an example.
    int_type: u32,
    // Is the IRQ being serviced at the moment?
    status: u32,
    pending: u32,
}

/// TODO change this to use a bitvector library
impl L2VicSlot {
    pub fn irqn_enable(&self, n: usize) -> bool {
        ((self.enable >> n) & 1) == 1
    }
    pub fn set_irqn_pending(&mut self, n: usize, value: bool) {
        self.pending &= !(1 << n)
    }
    pub fn set_irqn_enable(&mut self, n: usize, value: bool) {
        self.enable &= !(1 << n)
    }
    pub fn set_irqn_status(&mut self, n: usize, value: bool) {
        self.status &= !(1 << n)
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
            L2VicRegister::EnableClear => {
                self.slots[slot].enable &= !data;
            }
            L2VicRegister::Type => {
                self.slots[slot].int_type = data;
            }
            L2VicRegister::Clear => {
                self.slots[slot].clear = data;
            }
            _ => todo!(),
        }

        Ok(())
    }
}

impl EventControllerImpl for L2Vic {
    /// See l2vic_update_all for more details
    /// in hw/intc/l2vic.c.
    ///
    /// This function will retrieve and execute the latest interrupt
    /// based on which interrupts are currently pending.
    ///
    /// TODO: optimization as needed.
    fn next(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        _peripherals: &mut Peripherals,
    ) -> Result<InterruptExecuted, UnknownError> {
        // We aren't going to do anything until
        // VID is cleared - see l2vic_updated in hw/intc/l2vic.c QEMU.
        //
        // VID seemingly holds the value of the current IRQ that was raised.
        //
        // As an example, msee qemu-hexagon-testing's "levelint.c" test.
        // Also see hexagon-l2vic.rst in QUIC QEMU
        //
        // WARN: The QUIC implementation seems to use the
        // first bit set to find if any int_statuses are enabled.
        //
        // Is this not equivalent?
        if self.vid != 0 {
            // ------- TEST
            let mut int_statuses = false;
            for slot in &self.slots {
                if slot.status != 0 {
                    int_statuses = true;
                    break;
                }
            }
            assert_eq!(int_statuses, self.vid != 0);
            // --------- END TEST

            return Ok(InterruptExecuted::NotExecuted);
        }

        // Hexagon Programmer's Reference Manual:
        //
        // 11.9.2 SYSTEM MONITOR - "highest-priority interrupt 0... lowest-
        // priority interrupt 31"
        //
        // Go through IRQ numbers from lowest to highest priority,
        // and raise the highest-priority IRQ.

        let mut irq = None;
        for slot in &self.slots {
            // Now go through the IRQs
            // As each slot is 32 bits, the IRQ is 32 bits
            for i in 0..32 {
                // This means the IRQ must be executed, as it
                // was latched.
                if slot.irqn_enable(i) && slot.irqn_pending(i) {
                    irq = Some(i);
                    break;
                }
            }
        }

        match irq {
            Some(irq) => self
                .execute(irq as i32, cpu, mmu)
                .with_context(|| "couldn't execute pending interrupt"),
            None => Ok(InterruptExecuted::NotExecuted),
        }
    }

    /// This will effectively set this IRQ to pending, and put it in the
    /// IRQ queue.
    ///
    /// This means when the next event are checked and executed,
    /// in `next`, this event an be considered.
    ///
    /// TODO Priority and use a queue to avoid performance issues
    fn latch(&mut self, event: ExceptionNumber) -> Result<(), ActivateIRQnError> {
        let irq = event as usize;
        self.slots[irq].set_irqn_pending(irq, true);
        Ok(())
    }

    /// See l2vic_update for more details
    /// in hw/intc/l2vic.c.
    fn execute(
        &mut self,
        irq_n: ExceptionNumber,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Result<InterruptExecuted, ActivateIRQnError> {
        // The VID is found by looking at interrupt groups
        // Each group has an IRQ encoded for each slot and some
        // other magic..
        //
        //
        // IRQ number -> interrupt groups. there are 4
        // Interrupt group is array each slots
        // get slot, and the VID is the last 3 bits of the irq
        // times four shifted right
        //
        // (irq mod 8) * 4
        // vid 2 bits
        //
        // slice mmmm mmmm mmmm mmmm mmmm mmmm mmmm mmmm
        //
        //
        // It seems like there is only one VID
        // as the "interrupt groups" are never written.

        // Un-enable and un-pending the IRQ.

        // It looks like we only have one VID
        // in use since no other VIDs are setup in FW,
        // So we shall trigger the IRQ
        let irq = irq_n as usize;
        let slot = &mut self.slots[irq / L2VIC_NUM_SLOTS as usize];

        slot.set_irqn_status(irq, true);
        slot.set_irqn_enable(irq, false);
        slot.set_irqn_pending(irq, false);

        // The L2vic has four signals (VID0-3) to interrupt the CPU,
        // and each IRQ handled by the L2vic is signaled by
        // raising VID corresponding to the IRQ, according to QEMU
        // documentation.
        //
        // It looks like we only have one VID in use
        // since no other VIDs are setup in FW, so we shall trigger the IRQ
        // on the one VID.
        self.vid = irq as u32;

        // Now invoke the interrupt handler with IRQ 2.
        interrupt_handler(cpu, mmu, HexagonInterruptType::Int2 as ExceptionNumber)?;
        todo!("l2vic execute")
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

/// WARN: this should always be triggered at the end of a packet, after the pc has
/// been incremented, so the Elr should be set to the pc
///
/// This should only be done if the interrupt number is 0?
pub fn interrupt_handler(
    cpu: &mut dyn CpuBackend,
    mmu: &mut Mmu,
    interrupt_number: ExceptionNumber,
) -> Result<(), UnknownError> {
    // get cause, if the cause is 0 then we need to do the angel stuff
    let ssr = Ssr::new_with_raw_value(
        cpu.read_register::<u32>(HexagonRegister::Ssr)
            .with_context(|| "couldn't read ssr in interrupt")?,
    );

    info!("interrupt number is {}", interrupt_number);

    if ssr.cause() == 0 && interrupt_number == HexagonInterruptType::Trap0 as i32 {
        let swi_no = cpu
            .read_register::<u32>(HexagonRegister::R0)
            .with_context(|| "couldn't read r0 in interrupt")?;
        let arg = cpu
            .read_register::<u32>(HexagonRegister::R1)
            .with_context(|| "couldn't read r1 in interrupt")?;

        // Some other useful ones to implement
        // 0x15 - get cmdline
        // 0x16 - heap?

        if swi_no == 0x43 {
            print!("{}", arg as u8 as char);
        }
        // SYS_WRITE
        else if swi_no == 0x5 {
            let arg = arg as u64;
            let fileno = mmu.read_u32_le_virt_data(arg, cpu).unwrap();
            let ptr = mmu.read_u32_le_virt_data(arg + 4, cpu).unwrap();
            let bytes = mmu.read_u32_le_virt_data(arg + 8, cpu).unwrap();

            let mut data = vec![0; bytes as usize];
            mmu.virt_read_data(ptr as u64, &mut data, cpu).unwrap();

            let data_str = str::from_utf8_mut(&mut data).unwrap().to_owned();
            info!("SYS_WRITE no:{fileno} data:{data:x?} bytes:{bytes} str:{data_str}");

            cpu.write_register(HexagonRegister::R0, 0u32)
                .with_context(|| "couldn't write r0 for SYS_WRITE")?;
        }
        // SYS_CLOSE
        else if swi_no == 0x2 {
            // auto success
            cpu.write_register(HexagonRegister::R0, 0u32)
                .with_context(|| "couldn't write r0 for SYS_CLOSE")?;
        } else {
            info!("unimplemented trap: trap0 swi_no is 0x{swi_no:x}, arg 0x{arg:x}");
        }

        // There are some mailboxes in trap0 that are
        // used depending on the hexagon runtime
    }

    // get evb which is the interrupt vector base
    let evb = cpu
        .read_register::<u32>(HexagonRegister::Evb)
        .with_context(|| "couldn't read interrupt vector base")?;
    let jump_point = evb + (interrupt_number * 4) as u32;

    info!("interrupt jumping to {:x}", jump_point);

    // set elr to pc
    let pc = cpu
        .pc()
        .with_context(|| "couldn't get pc to write to elr")?;

    info!("interrupt setting elr to {:x}", pc);

    cpu.write_register(HexagonRegister::Elr, pc)
        .with_context(|| "couldn't write old pc to elr")?;

    cpu.write_register(HexagonRegister::Pc, jump_point)
        .with_context(|| "couldn't write interrupt jump point to pc")?;

    Ok(())
}
