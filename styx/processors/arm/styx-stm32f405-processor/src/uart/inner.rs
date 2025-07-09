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
//! Emulation of UART/USART controller for STM32F405
use derivative::Derivative;
use num_derive::ToPrimitive;
use std::{collections::VecDeque, mem::size_of};
use styx_core::prelude::*;
use styx_peripherals::uart::{IntoUartImpl, UartImpl};
use styx_stm32f405_sys::interrupt::Interrupt;
use tokio::sync::broadcast;
use tracing::{debug, trace, warn};

use styx_stm32f405_sys::{
    generic::FromBytes, uart4, uart5, usart1, usart2, usart3, usart6, Uart4, Uart5, Usart1, Usart2,
    Usart3, Usart6,
};

// # Safety
// These two unsafe blocks are performing hardware initialization,
// so it should use the sys_reset/register_clear methods
//
// in other words "permissions have no bearing here"
macro_rules! reset_usart_regs {
    ($regs:ident, $mmu:ident, $base:ident) => {
        unsafe {
            // Reset all registers in the USART block.
            $regs.cr1().sys_reset();
            $regs.cr2().sys_reset();
            $regs.cr3().sys_reset();
            $regs.sr().sys_reset();
            $regs.dr().sys_reset();
            $regs.brr().sys_reset();
            $regs.gtpr().sys_reset();
        }
        // Write the reset values back to memory.
        $mmu.data()
            .write($base)
            .bytes($regs.as_bytes_ref())
            .unwrap();
    };
}

macro_rules! reset_uart_regs {
    ($regs:ident, $mmu:ident, $base:ident) => {
        unsafe {
            // Reset all registers in the UART block.
            $regs.cr1().sys_reset();
            $regs.cr2().sys_reset();
            $regs.cr3().sys_reset();
            $regs.sr().sys_reset();
            $regs.dr().sys_reset();
            $regs.brr().sys_reset();
        }
        // Write the reset values back to memory.
        $mmu.data()
            .write($base)
            .bytes($regs.as_bytes_ref())
            .unwrap();
    };
}

pub enum RegisterBlocks {
    Uart4(uart4::RegisterBlock),
    Uart5(uart5::RegisterBlock),
    Usart1(usart1::RegisterBlock),
    Usart2(usart2::RegisterBlock),
    Usart3(usart3::RegisterBlock),
    Usart6(usart6::RegisterBlock),
}

pub struct DataTerminals {
    // note: baud rate and noise handling are abstracted over as data
    // transfer is emulated atomically and noiselessly
    // also note: the processor abstracts the transmission and recieving registers as 1,
    // but physically there is 2
    // also note: UART in this processor supports 8 and 9 bit transmission, but right
    // now we do not support 9-bit mode (there's an issue on this)
    tdr: u8,
    rdr: u8,
    tdr_empty: bool,
    rdr_not_empty: bool,
    tx_enabled: bool,
    rx_enabled: bool,
    tx_complete: bool,
    overrun_condition: bool, // communicates to the above layer that conditions are causing overrun
}

impl DataTerminals {
    pub fn new() -> Self {
        Self {
            tdr: 0x00,
            rdr: 0x00,
            tdr_empty: true,
            rdr_not_empty: false,
            tx_enabled: false,
            rx_enabled: false,
            tx_complete: false,
            overrun_condition: false,
        }
    }

    pub fn read_from_rdr(&mut self) -> Option<u8> {
        self.clear_overrrun_condition();

        if self.rdr_not_empty {
            self.clear_rdr_not_empty();
            return Some(self.rdr);
        }

        // technically reading from an empty DR gives undefined data,
        // we model that as None
        None
    }

    pub fn receive_to_rdr(&mut self, data: u8) {
        // check for overrun error
        if self.rdr_not_empty() {
            self.set_overrun_condition();
            return;
        }

        self.rdr = data;
        self.set_rdr_not_empty();
    }

    pub fn send_from_tdr(&mut self) -> Option<u8> {
        if !self.tdr_empty {
            self.set_tdr_empty();
            self.set_tx_complete();
            return Some(self.tdr);
        }

        None
    }

    pub fn write_to_tdr(&mut self, data: u8) {
        self.tdr = data;
        self.clear_tdr_empty();
    }

    pub fn set_tdr_empty(&mut self) {
        self.tdr_empty = true;
    }

    pub fn clear_tdr_empty(&mut self) {
        self.tdr_empty = false;
    }

    pub fn tdr_empty(&mut self) -> bool {
        self.tdr_empty
    }

    pub fn set_rdr_not_empty(&mut self) {
        self.rdr_not_empty = true;
    }

    pub fn clear_rdr_not_empty(&mut self) {
        self.rdr_not_empty = false;
    }

    pub fn rdr_not_empty(&mut self) -> bool {
        self.rdr_not_empty
    }

    pub fn tx_enable(&mut self) {
        self.tx_enabled = true
    }

    pub fn rx_enable(&mut self) {
        self.rx_enabled = true
    }

    pub fn tx_disable(&mut self) {
        self.tx_enabled = false
    }

    pub fn tx_enabled(&mut self) -> bool {
        self.tx_enabled
    }

    pub fn rx_enabled(&mut self) -> bool {
        self.rx_enabled
    }

    pub fn set_tx_complete(&mut self) {
        self.tx_complete = true
    }

    pub fn clear_tx_complete(&mut self) {
        self.tx_complete = false
    }

    pub fn tx_complete(&mut self) -> bool {
        self.tx_complete
    }

    pub fn set_overrun_condition(&mut self) {
        self.overrun_condition = true
    }

    pub fn clear_overrrun_condition(&mut self) {
        self.overrun_condition = false
    }

    pub fn overrun_condition(&mut self) -> bool {
        self.overrun_condition
    }
}

#[derive(Default)]
pub struct UsartInterrupt {
    interrupt: bool,
    interrupt_enabled: bool,
    /// Captures whether or not the most recent state change should trigger an interrupt event to
    /// get queued.
    trigger_event: bool,
}

impl UsartInterrupt {
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

    pub fn enable(&mut self) {
        let prev_setting = self.interrupt_enabled;
        self.interrupt_enabled = true;

        // If the interrupt goes from disabled to enabled, then we'll want to fire an interrupt if
        // it is set. We don't worry about situations where the interrupt is getting disabled, or
        // the interrupt was already enabled.
        self.trigger_event = !prev_setting && self.interrupt_enabled && self.interrupt;
    }

    pub fn disable(&mut self) {
        self.interrupt_enabled = false;
    }

    pub fn enabled(&self) -> bool {
        self.interrupt_enabled
    }
}

/// USART Interrupt Types. See **[STM32F405xx: USART Interrupts](https://www.st.com/resource/en/reference_manual/dm00031020-stm32f405-415-stm32f407-417-stm32f427-437-and-stm32f429-439-advanced-arm-based-32-bit-mcus-stmicroelectronics.pdf#page=1009)** for
/// details.
#[derive(Default)]
pub struct UsartInterruptControl {
    /// Transmit Data Register Empty
    pub int_txe: UsartInterrupt,

    /// Clear To Send
    pub int_cts: UsartInterrupt,

    /// Transmission Complete
    pub int_tc: UsartInterrupt,

    /// Recieved Data Ready to be Read
    pub int_rxne: UsartInterrupt,

    /// Overrun Error Detected
    pub int_ore: UsartInterrupt,

    /// Idle Line Detected.
    /// We don't use this in emulation
    _int_idle: UsartInterrupt,

    /// Parity Error.
    /// We don't use this in emulation
    _int_pe: UsartInterrupt,

    /// Break Flag.
    /// We don't use this in emulation
    _int_lbd: UsartInterrupt,

    /// Noise Flag, Overrun error, and Framing Error when
    /// using multibuffer communication (with DMA).
    /// We don't use this in emulation
    _int_nf_ore_fe: UsartInterrupt,

    // Boolean field used to control the clearing of the overrun
    // and transmission complete interrupts and status bits. They
    // are cleared by a software sequence starting with reading from
    // the status register.
    recent_sr_read: bool,
}

impl UsartInterruptControl {
    pub fn recent_sr_read(&self) -> bool {
        self.recent_sr_read
    }

    pub fn set_recent_sr_read(&mut self) {
        self.recent_sr_read = true;
    }

    pub fn clear_recent_sr_read(&mut self) {
        self.recent_sr_read = false;
        if self.int_cts.active() {}
    }
}
/// Hardware Abstraction Layer for the STM32F405 USART.
pub struct UsartHalLayer {
    pub registers: RegisterBlocks,
    pub data_terminals: DataTerminals,
    pub interrupt_control: UsartInterruptControl,
    // XXX: We capture when a client subscribes, but not when they disconnect.
    client_connected: bool,
    pub enabled: bool,
}

#[derive(ToPrimitive, PartialEq, Eq, Clone, Copy, Debug)]
pub enum Port {
    UsartOne = 1,
    UsartTwo = 2,
    UsartThree = 3,
    UartFour = 4,
    UartFive = 5,
    UsartSix = 6,
}

impl std::fmt::Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", *self as u32)
    }
}

pub(crate) const USART_REG_BLOCK_SIZE: usize = size_of::<usart1::RegisterBlock>();
pub(crate) const UART_REG_BLOCK_SIZE: usize = size_of::<uart4::RegisterBlock>();

impl UsartHalLayer {
    /// Construct a new abstraction for a USART/UART port
    pub fn new(port: Port) -> Self {
        let init_bytes_usart: [u8; USART_REG_BLOCK_SIZE] = [0u8; USART_REG_BLOCK_SIZE];
        let init_bytes_uart: [u8; UART_REG_BLOCK_SIZE] = [0u8; UART_REG_BLOCK_SIZE];
        let registers = match port {
            Port::UsartOne => unsafe {
                let regs = usart1::RegisterBlock::from_bytes(&init_bytes_usart).unwrap();
                RegisterBlocks::Usart1(regs)
            },
            Port::UsartTwo => unsafe {
                let regs = usart2::RegisterBlock::from_bytes(&init_bytes_usart).unwrap();
                RegisterBlocks::Usart2(regs)
            },
            Port::UsartThree => unsafe {
                let regs = usart3::RegisterBlock::from_bytes(&init_bytes_usart).unwrap();
                RegisterBlocks::Usart3(regs)
            },
            Port::UartFour => unsafe {
                let regs = uart4::RegisterBlock::from_bytes(&init_bytes_uart).unwrap();
                RegisterBlocks::Uart4(regs)
            },
            Port::UartFive => unsafe {
                let regs = uart5::RegisterBlock::from_bytes(&init_bytes_uart).unwrap();
                RegisterBlocks::Uart5(regs)
            },
            Port::UsartSix => unsafe {
                let regs = usart6::RegisterBlock::from_bytes(&init_bytes_usart).unwrap();
                RegisterBlocks::Usart6(regs)
            },
        };

        UsartHalLayer {
            registers,
            enabled: false,
            data_terminals: DataTerminals::new(),
            interrupt_control: Default::default(),
            client_connected: false,
        }
    }

    pub fn reset(&mut self, mmu: &mut Mmu) -> Result<(), UnknownError> {
        self.data_terminals = DataTerminals::new();
        self.interrupt_control = Default::default();
        self.client_connected = false;
        self.enabled = false;
        match &self.registers {
            RegisterBlocks::Usart1(regs) => {
                let base = Usart1::BASE;
                reset_usart_regs!(regs, mmu, base);
            }
            RegisterBlocks::Usart2(regs) => {
                let base = Usart2::BASE;
                reset_usart_regs!(regs, mmu, base);
            }
            RegisterBlocks::Usart3(regs) => {
                let base = Usart3::BASE;
                reset_usart_regs!(regs, mmu, base);
            }
            RegisterBlocks::Uart4(regs) => {
                let base = Uart4::BASE;
                reset_uart_regs!(regs, mmu, base);
            }
            RegisterBlocks::Uart5(regs) => {
                let base = Uart5::BASE;
                reset_uart_regs!(regs, mmu, base);
            }
            RegisterBlocks::Usart6(regs) => {
                let base = Usart6::BASE;
                reset_usart_regs!(regs, mmu, base);
            }
        }
        Ok(())
    }

    pub fn enable(&mut self) {
        self.enabled = true;
    }

    pub fn disable(&mut self) {
        self.enabled = false;
    }

    pub fn enabled(&mut self) -> bool {
        self.enabled
    }
}

pub struct UartPortBuilder {
    port: Port,
    base_address: u32,
    tx_rx_irqn: ExceptionNumber,
}

impl UartPortBuilder {
    pub fn new(port: Port) -> Self {
        let base_address;
        let tx_rx_irqn;
        match port {
            Port::UsartOne => {
                base_address = Usart1::BASE;
                tx_rx_irqn = Interrupt::USART1 as ExceptionNumber;
            }
            Port::UsartTwo => {
                base_address = Usart2::BASE;
                tx_rx_irqn = Interrupt::USART2 as ExceptionNumber;
            }
            Port::UsartThree => {
                base_address = Usart3::BASE;
                tx_rx_irqn = Interrupt::USART3 as ExceptionNumber;
            }
            Port::UartFour => {
                base_address = Uart4::BASE;
                tx_rx_irqn = Interrupt::UART4 as ExceptionNumber;
            }
            Port::UartFive => {
                base_address = Uart5::BASE;
                tx_rx_irqn = Interrupt::UART5 as ExceptionNumber;
            }
            Port::UsartSix => {
                base_address = Usart6::BASE;
                tx_rx_irqn = Interrupt::USART6 as ExceptionNumber;
            }
        };

        Self {
            port,
            base_address,
            tx_rx_irqn,
        }
    }
}

impl IntoUartImpl for UartPortBuilder {
    fn new(
        self,
        mosi_tx: broadcast::Receiver<u8>,
        miso_rx: broadcast::Sender<u8>,
        interface_id: String,
    ) -> Result<Box<dyn UartImpl>, UnknownError> {
        Ok(Box::new(UartPortInner {
            interface_id,
            base_address: self.base_address,
            tx_rx_irqn: self.tx_rx_irqn,
            inner_hal: UsartHalLayer::new(self.port),
            rx_fifo: VecDeque::default(),
            miso_stream: miso_rx,
            mosi_stream: mosi_tx,
        }))
    }
}

// USART Controller port emulation
#[derive(Derivative)]
#[derivative(Debug)]
pub struct UartPortInner {
    pub interface_id: String,
    base_address: u32,
    // USART Interrupt Requests described in Table 148 of the STM32F405 TRM.
    tx_rx_irqn: ExceptionNumber,
    #[derivative(Debug = "ignore")]
    inner_hal: UsartHalLayer,
    rx_fifo: VecDeque<u8>,
    miso_stream: broadcast::Sender<u8>,
    mosi_stream: broadcast::Receiver<u8>,
}

// is okay
unsafe impl Send for UartPortInner {}
unsafe impl Sync for UartPortInner {}

impl UartPortInner {
    /// Get a [`MutexGuard`] of the inner uart data struct
    pub fn inner_hal(&mut self) -> &mut UsartHalLayer {
        &mut self.inner_hal
    }

    pub fn queue_interrupt(&self, ev: &mut dyn EventControllerImpl) {
        ev.latch(self.tx_rx_irqn).unwrap();
    }

    /// called from within the guest write hook to the data register,
    /// this adds a transmission to the broadcast channel
    pub fn guest_transmit_data(&self, value: u8) {
        let subscribers = self.miso_stream.send(value).unwrap();

        trace!("Send new value to {} subscriber", subscribers);
    }

    pub fn checked_generate_receive_interrupts(&mut self, ev: &mut dyn EventControllerImpl) {
        // first, check for and generate overrun error
        if self.inner_hal.data_terminals.overrun_condition() {
            self.inner_hal.interrupt_control.int_ore.set();

            if self.inner_hal.interrupt_control.int_ore.triggered() {
                // latch the event with the event controller
                self.queue_interrupt(ev);
            }
        }

        // now check that data is ready to read
        if self.inner_hal.data_terminals.rdr_not_empty {
            self.inner_hal.interrupt_control.int_rxne.set();

            if self.inner_hal.interrupt_control.int_rxne.triggered() {
                // now latch the event with the event controller
                self.queue_interrupt(ev);
            }
        }
    }

    pub fn checked_generate_transmit_interrupt(&mut self, ev: &mut dyn EventControllerImpl) {
        // annoying to have to pass in the hal, but prevents deadlock
        // first check if the USART is ready to transmit more data
        if self.inner_hal.data_terminals.tdr_empty() {
            self.inner_hal.interrupt_control.int_txe.set();

            if self.inner_hal.interrupt_control.int_txe.triggered() {
                // now latch the event with the event controller
                self.queue_interrupt(ev);
            }
        }

        // now check if transmission is complete
        // note: for now this happens simultaneously with the previous
        if self.inner_hal.data_terminals.tx_complete() {
            self.inner_hal.interrupt_control.int_tc.set();

            if self.inner_hal.interrupt_control.int_tc.triggered() {
                // now latch the event with the event controller
                self.queue_interrupt(ev);
            }
        }
    }

    pub fn base_address(&self) -> u32 {
        self.base_address
    }

    /// checks uart mosi for bytes and gives to buffer
    fn grab_bytes(&mut self) {
        loop {
            let res = self.mosi_stream.try_recv();
            match res {
                Ok(data) => self.rx_fifo.push_back(data),
                Err(broadcast::error::TryRecvError::Empty) => break,
                Err(broadcast::error::TryRecvError::Closed) => {
                    warn!("uart mosi stream closed??");
                    break;
                }
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    warn!("uart mosi stream lagged {n} items");
                    break;
                }
            }
        }
    }
}

impl UartImpl for UartPortInner {
    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        trace!("Uart{} .reset_state()", self.interface_id);
        self.inner_hal.reset(&mut proc.core.mmu).unwrap();
        debug!("Uart{} .register_hooks()", self.interface_id);
        self.register_mmio_hooks(proc.core.cpu.as_mut())?;

        Ok(())
    }

    fn post_event_hook(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _event_controller: &mut dyn EventControllerImpl,
    ) -> Result<(), UnknownError> {
        trace!("UART{} got post_event_hook", self.interface_id);
        // TODO: UART vs USART technically
        Ok(())
    }

    fn irqs(&self) -> Vec<ExceptionNumber> {
        vec![self.tx_rx_irqn as ExceptionNumber]
    }

    fn tick(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        event_controller: &mut dyn EventControllerImpl,
    ) -> Result<(), UnknownError> {
        // get bytes from mosi buffer
        self.grab_bytes();

        // latch interrupt if uart data is available
        // this will latch multiple times even if no uart data arrived but uart data is available
        // ... probably not an issue :D
        if let Some(front) = self.rx_fifo.pop_front() {
            trace!("latching!!");
            // now latch the event with the event controller
            self.inner_hal.data_terminals.receive_to_rdr(front);
            self.checked_generate_receive_interrupts(event_controller);
        }
        Ok(())
    }
}
