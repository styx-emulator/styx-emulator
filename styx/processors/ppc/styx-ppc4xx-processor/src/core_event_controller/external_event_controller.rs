// SPDX-License-Identifier: BSD-2-Clause
//! Implementation of the "LogiCORE IP XPS Interrupt Controller"
//!
//! This controller concentrates multiple interrupts from peripherals
//! into a single output.  i.e. peripherals generate interrupts in
//! this controller which then can generate an ExternalInput event in
//! the main processor interrupt controller.
//!
//! Registers:
//!
//! Interrupt Status Register (ISR):
//!
//! Offset: 0x0
//! Reset: 0x0
//! Access: RW
//!
//!
//! Interrupt Enable Register (IER):
//!
//! Offset: +0x8
//! Reset: 0x0
//! Access: RW
//!
//!
//! Interrupt Acknowledge Register (IAR):
//!
//! Offset: +0xC
//! Reset: 0x0
//! Access: W
//!
//!
//! Set Interrupt Enable (SIE):
//!
//! Offset: +0x10
//! Reset: 0x0
//! Access: W
//!
//! SIE is a location used to set IER bits in a single atomic operation,
//! rather than using a read/modify/write sequence.  Writing a one to a
//! bit location in SIE will set the corresponding bit in the IER.
//!
//!
//! Clear Interrupt Enable (CIE):
//!
//! Offset: +0x14
//! Reset: 0x0
//! Access: W
//!
//! CIE is a location used to clear IER bits in a single atomic operation,
//! rather than using a read/modify/write sequence.  Writing a one to a
//! bit location in CIE will clear the corresponding bit in the IER.
//!
//!
//! Master Enable Register (MER):
//!
//! Offset: +0x1C
//! Reset: 0x0
//! Access: RW
//!
//!  Bit(s)  | Name     | Access     | Reset | Description
//! ----------------------------------------------------------
//!  0 - 29  | reserved | -          | -     | -
//!  30      | HIE      | write once | 0     | disable software interrupts, enable hardware interrupts
//!  31      | ME       | RW         | 0     | enable output interrupt
//!
//! Writing a 1 to the ME bit enables the IRQ output signal. Writing a 0
//! to the ME bit disables the IRQ output, effectively masking all
//! interrupt inputs.  The HIE bit is a write once bit. At reset this bit
//! is reset to zero, allowing software to write to the ISR to generate
//! interrupts for testing purposes, and disabling any hardware interrupt
//! inputs.  Writing a one to this bit enables the hardware interrupt
//! inputs and disables software generated inputs. Writing a one also
//! disables any further changes to this bit until the device has been
//! reset.  Writing ones or zeros to any other bit location does nothing.
//! When read, this register will reflect the state of the ME and HIE bits.
//!
//!
//! Optional Registers, Not Implemented:
//! - Interrupt Pending Register (IPR)
//! - Interrupt Vector Register (IVR)
//!
use styx_core::{
    hooks::{HookUserData, MemoryWriteHook},
    memory::{helpers::WriteExt, Mmu},
    prelude::{CoreHandle, CpuBackend},
    sync::sync::{Arc, Weak},
};

use super::{Event, UnknownError};

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use tracing::debug;

// Base address for the external interrupt controller mmrs
const INTC_BASE: u64 = 0x70800000;

const ISR_OFFSET: u64 = INTC_BASE;
const IER_OFFSET: u64 = INTC_BASE + 0x08;
const IAR_OFFSET: u64 = INTC_BASE + 0x0C;
const SIE_OFFSET: u64 = INTC_BASE + 0x10;
const CIE_OFFSET: u64 = INTC_BASE + 0x14;
const MER_OFFSET: u64 = INTC_BASE + 0x1C;

const MER_MASTER_ENABLE: u32 = 0x1;
const MER_HARDWARE_ENABLE: u32 = 0x2;

const EVENT_UART: u32 = 1 << 6;
const EVENT_ETHERNET: u32 = 1 << 5;

pub struct ExternalEventController {
    self_ref: Weak<ExternalEventController>,
    // ME bit from the MER
    master_enable: AtomicBool,
    // HIE bit from the MER
    hardware_enable: AtomicBool,
    // interrupt enable register
    ier: AtomicU32,
    // interrupt status register
    isr: AtomicU32,
}

impl ExternalEventController {
    pub fn new_arc() -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            self_ref: me.clone(),
            master_enable: false.into(),
            hardware_enable: false.into(),
            ier: 0.into(),
            isr: 0.into(),
        })
    }

    #[inline]
    /// Each external event maps to a single bit in the 4 byte registers.
    /// IF the event doesn't belong to an external event, returns None
    fn map_event_to_u32(&self, event: Event) -> Option<u32> {
        match event {
            Event::Uart => Some(EVENT_UART),
            Event::Ethernet => Some(EVENT_ETHERNET),
            _ => None,
        }
    }

    /// Sets the ISR to active for this event.  If the event is enabled and the master
    /// enable flag is set, then return true.  A return value of true indicates to the
    /// main controller to latch an ExternalInput event
    pub fn handle_event(&self, event: Event) -> bool {
        if let Some(e) = self.map_event_to_u32(event) {
            debug!("external controller handling event: {:?}", event);

            self.isr.fetch_or(e, Ordering::AcqRel);

            return self.master_enable.load(Ordering::Acquire)
                && (self.ier.load(Ordering::Acquire) & e != 0);
        }

        false
    }

    pub fn register_hooks(&self, cpu: &mut dyn CpuBackend) -> Result<(), UnknownError> {
        cpu.mem_write_hook(
            ISR_OFFSET,
            MER_OFFSET,
            Box::new(IntCWHook(self.self_ref.upgrade().unwrap())),
        )?;
        {
            let me = self.self_ref.upgrade().unwrap();
            cpu.mem_read_hook(
                ISR_OFFSET,
                MER_OFFSET,
                Box::new(move |proc: CoreHandle, address, value, data: &mut [u8]| {
                    let me = me.clone();
                    intc_r_hook(proc, address, value, data, me)
                }),
            )?;
        }

        Ok(())
    }

    pub fn reset(&self, mmu: &mut Mmu) -> Result<(), UnknownError> {
        // clear the memory mapped registers
        mmu.data().write(ISR_OFFSET).bytes(&[0; 0x20])?;

        // reset control/status flags
        self.hardware_enable.store(false, Ordering::Release);
        self.master_enable.store(false, Ordering::Release);
        self.ier.store(0, Ordering::Release);
        self.isr.store(0, Ordering::Release);

        Ok(())
    }
}

/// Helper function to convert an array of big endian bytes to a u32
fn u32_from_be_word(data: &[u8], size: u32) -> u32 {
    debug_assert!(size <= 4, "writes >4 bytes not supported");

    let mut u32_data = [0u8; 4];
    let bytes_to_copy = size as usize;
    u32_data[0..bytes_to_copy].copy_from_slice(&data[0..bytes_to_copy]);
    u32::from_be_bytes(u32_data)
}

struct IntCWHook(Arc<ExternalEventController>);
impl MemoryWriteHook for IntCWHook {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        debug!(
            "[{:x}] Write to INTC: address=0x{:x}, size={}, data={:?}",
            proc.cpu.pc().unwrap(),
            address,
            size,
            data
        );

        let val: u32 = u32_from_be_word(data, size);

        let controller = &self.0;
        match address {
            ISR_OFFSET => {
                // TODO: writes to ISR should do nothing if controller.hardware_enable is set
            }
            IER_OFFSET => {
                controller.ier.store(val, Ordering::Release);
            }
            IAR_OFFSET => {
                controller.isr.fetch_and(!val, Ordering::AcqRel);
            }
            SIE_OFFSET => {
                controller.ier.fetch_or(val, Ordering::AcqRel);
            }
            CIE_OFFSET => {
                controller.ier.fetch_and(!val, Ordering::AcqRel);
            }
            MER_OFFSET => {
                if val & MER_MASTER_ENABLE != 0 {
                    controller.master_enable.store(true, Ordering::Release);
                } else {
                    controller.master_enable.store(false, Ordering::Release);
                }

                if !controller.hardware_enable.load(Ordering::Acquire)
                    && val & MER_HARDWARE_ENABLE != 0
                {
                    controller.hardware_enable.store(true, Ordering::Release);
                }
            }
            _ => {
                // we shouldn't ever get here, but just in case
                debug!("write to unimplemented INTC register.");
            }
        };
        Ok(())
    }
}

fn intc_r_hook(
    proc: CoreHandle,
    address: u64,
    size: u32,
    data: &mut [u8],
    userdata: HookUserData,
) -> Result<(), UnknownError> {
    debug!(
        "[{:x}] Read from INTC: address=0x{:x}, size={}, data={:?}",
        proc.cpu.pc().unwrap(),
        address,
        size,
        data
    );

    let controller: Arc<ExternalEventController> = userdata.downcast().unwrap();

    // if the guest reads the ISR, replace it with our version
    if address == ISR_OFFSET {
        let isr = controller.isr.load(Ordering::Acquire);
        let actual_data = isr.to_be_bytes();
        data[..=3].copy_from_slice(&actual_data);
    }
    Ok(())
}
