// SPDX-License-Identifier: BSD-2-Clause
//! Emulates Uart controller for K21
use std::{collections::VecDeque, mem::size_of};
use styx_core::prelude::*;
use styx_cyclone_v_hps_sys::{generic::FromBytes, uart0};

pub enum UartPortNumber {
    One,
    Zero,
}

/// Cyclone V has 128-byte transmit and receive buffers.
/// See the Cyclone V Hard Processor System TRM, chapter 22.
/// This is also the value in the cpr register's fifo_mode.
pub const TX_RX_FIFO_BUFFERS_SIZE: usize = 128;

pub struct UartFifo {
    pub enabled: bool,
    pub tx_empty_threshold: usize,
    pub rx_trigger_level: usize,
    pub size: usize,
    tx_fifo: VecDeque<u8>,
    rx_fifo: VecDeque<u8>,
}

impl UartFifo {
    pub fn new(size: usize) -> Self {
        // TODO: make a static sized queue to emulate proper fifosize
        // TODO: re-evaluate if the above is actually needed
        let mut tx_fifo = VecDeque::new();
        let mut rx_fifo = VecDeque::new();
        tx_fifo.reserve_exact(size);
        rx_fifo.reserve_exact(size);

        UartFifo {
            enabled: false,
            tx_empty_threshold: 0,
            rx_trigger_level: 0,
            size,
            tx_fifo,
            rx_fifo,
        }
    }

    pub fn rx_trigger_level_reached(&self) -> bool {
        self.rx_fifo.len() >= self.rx_trigger_level
    }

    pub fn tx_empty_threshold_reached(&self) -> bool {
        self.tx_fifo.len() <= self.tx_empty_threshold
    }

    // TODO: Should we check if the FIFO overflows? It might not make sense given the way we are
    // emulating this.
    pub fn rx_put(&mut self, byte: u8) {
        // TODO: Check if the FIFO is full, and fire the appropriate interrupt.
        // TODO: If the FIFO ever gets filled up, we need to set lsr.oe (overrun error).
        self.rx_fifo.push_back(byte);
    }

    pub fn rx_get(&mut self) -> u8 {
        // Send a byte if available, otherwise send a null byte.
        if self.rx_fifo.is_empty() {
            0
        } else {
            self.rx_fifo.pop_front().unwrap_or(0)
        }
    }

    pub fn rx_len(&mut self) -> usize {
        self.rx_fifo.len()
    }

    pub fn rx_clear(&mut self) {
        self.rx_fifo.clear();
    }

    pub fn rx_is_empty(&mut self) -> bool {
        self.rx_fifo.is_empty()
    }

    pub fn rx_is_full(&mut self) -> bool {
        self.rx_fifo.len() == self.size
    }
}

/// Certain registers can have multiple "views" (i.e. meanings and values) depending on the
/// processors state. One view is active, and thus being accessed during writes and reads, while
/// the others are hidden.  These "shadow registers" allow us to preserve all views and present
/// them to the guest at the appropriate times.
#[derive(Default)]
pub struct UartShadowRegs {
    pub dll_val: u32,
    pub dlh_val: u32,
    pub ier_val: u32,

    // Since the iir and fcr registers overlap, they do not have independent storage in the
    // register block structure. We cannot keep this data in the register block since we will still
    // use both registers in the block for parsing the register values.
    // Note: iir is generated on the fly, so we don't need to save it.
    pub fcr_val: u32,
}

#[derive(Default)]
pub struct UartInterrupt {
    interrupt: bool,
    interrupt_enabled: bool,
    /// Captures whether or not the most recent state change should trigger an interrupt event to
    /// get queued.
    trigger_event: bool,
}

impl UartInterrupt {
    pub fn active(&self) -> bool {
        self.interrupt && self.interrupt_enabled
    }

    pub fn triggered(&self) -> bool {
        self.trigger_event
    }

    pub fn set(&mut self) {
        let prev_setting = self.interrupt;
        self.interrupt = true;

        // If the interrupt goes from cleared to set and it is already enabled, we'll want to queue
        // an interrupt with the event manager. We don't worry about the situation where the
        // interrupt was already active, since an interrupt would already have been queued.
        self.trigger_event = !prev_setting && self.interrupt && self.interrupt_enabled;
    }

    pub fn clear(&mut self) {
        self.interrupt = false;
        self.trigger_event = false;
    }

    pub fn set_enabled(&mut self, status: bool) {
        let prev_setting = self.interrupt_enabled;
        self.interrupt_enabled = status;

        // If the interrupt goes from disabled to enabled, then we'll want to fire an interrupt if
        // it is set. We don't worry about situations where the interrupt is getting disabled, or
        // the interrupt was already enabled.
        self.trigger_event = !prev_setting && self.interrupt_enabled && self.interrupt;
    }
}

/// UART Interrupt Types describe in Table 22-4 of the Cyclone V Hard Processor System TRM.
#[derive(Default)]
pub struct UartInterruptControl {
    /// Transmit Hold Register Empty Interrupt (THRE) Interrupt (IER bit 7)
    /// This seems to actually be a mode rather than an interrupt, though the documentation is
    /// inconsistent.
    pub int_thre: UartInterrupt,

    /// Modem Status Interrupt (IER bit 3)
    /// - Fourth highest priority interrupt
    /// - Reading the Modem Status Register clears the Modem Status Interrupt.
    pub int_modem_status: UartInterrupt,

    /// Receiver Line Status Interrupt (IER bit 2)
    /// - Highest priority interrupt
    /// - Reading the Line Status Register clears the Receiver Line Status Interrupt.
    pub int_rx_line_status: UartInterrupt,

    /// Transmit Holding Register Empty Interrupt (IER bit 1)
    /// - Third highest priority interrupt
    /// - Clearing the interrupt (Cyclone V TRM Table 22-4):
    ///     - If the Transmit Holding Register Empty interrupt is the source of an interrupt,
    ///       reading the IIR register clears the interrupt.
    ///     - Writing into the transmit hold register (thr) clears the interrupt.
    pub int_tx_holding_empty: UartInterrupt,

    /// Receive Data Available Interrupt & Character Timeout Interrupt (if FIFO's enabled).
    /// (IER bit 0)
    /// - Second highest priority interrupt
    /// - Clearing the interrupt (Cyclone V TRM Table 22-4):
    ///     - Reading from the receive buffer register (rbr) clears the character timeout
    ///       interrupt.
    ///     - The FIFO dropping below the trigger level clears the received data available
    ///       interrupt.
    pub int_rx_data_aval_and_char_timeout: UartInterrupt,

    pub char_timeout: bool,
}

/// Cyclone V UART Interrupt ID encodings.
pub type CycloneVInterruptIds = uart0::iir::Id;

impl UartInterruptControl {
    pub fn highest_priority_active(&self) -> CycloneVInterruptIds {
        // Highest priority
        if self.int_rx_line_status.active() {
            CycloneVInterruptIds::Rxlinestat
        // Second highest priority
        } else if self.int_rx_data_aval_and_char_timeout.active() {
            // XXX: We don't currently do anything with char_timeout.
            if self.char_timeout {
                CycloneVInterruptIds::Chartimeout
            } else {
                CycloneVInterruptIds::Rxdatavailable
            }
        // Third highest priority
        } else if self.int_tx_holding_empty.active() {
            CycloneVInterruptIds::Thrempty
        // Fourth highest priority
        } else if self.int_modem_status.active() {
            CycloneVInterruptIds::Modemstat
        } else {
            CycloneVInterruptIds::Nointrpending
        }
    }
}

/// Hardware Abstraction Layer for the Cyclone V HPS UART.
pub struct UartHalLayer {
    pub registers: uart0::RegisterBlock,
    pub shadow_regs: UartShadowRegs,
    pub dlab_state: bool,
    pub request_to_send: bool,
    pub data_terminal_ready: bool,
    pub fifo: UartFifo,
    pub interrupt_control: UartInterruptControl,
    // XXX: We capture when a client subscribes, but not when they disconnect.
    client_connected: bool,

    pub base_addr: u64,
}

unsafe impl Sync for UartHalLayer {}

pub(crate) const UART_REG_BLOCK_SIZE: usize = size_of::<uart0::RegisterBlock>();

impl UartHalLayer {
    pub fn new(base_addr: u64) -> Self {
        let init_bytes: [u8; UART_REG_BLOCK_SIZE] = [0u8; UART_REG_BLOCK_SIZE];

        UartHalLayer {
            registers: unsafe { uart0::RegisterBlock::from_bytes(&init_bytes).unwrap() },
            fifo: UartFifo::new(TX_RX_FIFO_BUFFERS_SIZE),
            shadow_regs: Default::default(),
            interrupt_control: Default::default(),
            dlab_state: false,
            request_to_send: false,
            data_terminal_ready: false,
            client_connected: false,
            base_addr,
        }
    }

    fn reset_uart_regs(&mut self) {
        // # Safety
        // This unsafe block is performing hardware initialization,
        // so it should use the sys_reset/register_clear methods
        //
        // in other words "permissions have no bearing here"
        unsafe {
            // Reset all registers in the UART.
            self.registers.rbr_thr_dll().sys_reset();
            self.registers.ier_dlh().sys_reset();
            self.registers.lcr().sys_reset();
            self.registers.mcr().sys_reset();
            self.registers.lsr().sys_reset();
            self.registers.msr().sys_reset();
            self.registers.scr().sys_reset();
            self.registers.srbr().sys_reset();
            self.registers.sthr().sys_reset();
            self.registers.far().sys_reset();
            self.registers.tfr().sys_reset();
            self.registers.rfw().sys_reset();
            self.registers.usr().sys_reset();
            self.registers.tfl().sys_reset();
            self.registers.rfl().sys_reset();
            self.registers.srr().sys_reset();
            self.registers.srts().sys_reset();
            self.registers.sbcr().sys_reset();
            self.registers.sdmam().sys_reset();
            self.registers.sfe().sys_reset();
            self.registers.srt().sys_reset();
            self.registers.stet().sys_reset();
            self.registers.htx().sys_reset();
            self.registers.dmasa().sys_reset();
            self.registers.cpr().sys_reset();
            self.registers.ucv().sys_reset();
            self.registers.ctr().sys_reset();
        }

        // Save the reset values for the shadow registers.
        self.shadow_regs.ier_val = self.registers.ier_dlh().read().bits();

        // The iir and fcr registers overlap, so we explicitly reset fcr before reading it.
        // Resetting iir would change the value we get.
        unsafe {
            self.registers.fcr().sys_reset();
            self.shadow_regs.fcr_val = self.registers.fcr().sys_read().bits();
        }

        // dll and dlh aren't initially accessible, so we just default to 0.
        self.shadow_regs.dll_val = 0;
        self.shadow_regs.dlh_val = 0;
    }

    pub fn reset(&mut self, mmu: &mut Mmu) -> Result<(), UnknownError> {
        self.shadow_regs = Default::default();
        self.fifo.rx_clear();
        self.interrupt_control = Default::default();
        self.dlab_state = false;
        self.request_to_send = false;
        self.data_terminal_ready = false;
        self.client_connected = false;

        self.reset_uart_regs();

        // Write the reset values back to memory.
        mmu.write_data(self.base_addr, self.registers.as_bytes_ref())
            .unwrap();

        Ok(())
    }

    pub fn client_connected(&self) -> bool {
        self.client_connected
    }
}
