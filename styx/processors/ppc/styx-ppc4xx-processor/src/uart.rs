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
//! Source: XPS UART Lite (v1.02a) Data Sheet (DS571)
//!     <https://docs.amd.com/v/u/en-US/xps_uartlite>
//!
//! Writing a read only register has no effect
//! Reading a write only register returns 0
//! Registers are defined for 32-bit access only. Any partial word accesses
//! (byte or halfword) have undefined results and returns a bus error.
//!
//! Registers:
//!
//! UART Rx FIFO Register
//!
//! Offset: +0x0
//! Reset Value: 0x0
//! Access: Read only
//!
//!  Bit(s)  | Name     | Access | Reset | Description
//! ----------------------------------------------------------
//!  0 - 23  | reserved | -      | 0     | not used
//!  24 - 31 | Rx Data  | read   | 0     | UART receive data
//!
//!
//! UART Tx FIFO Register
//!
//! Offset: +0x4
//! Reset Value: 0x0
//! Access: Write only
//!
//!  Bit(s)  | Name     | Access | Reset | Description
//! ----------------------------------------------------------
//!  0 - 23  | reserved | -      | 0     | not used
//!  24 - 31 | Tx Data  | write  | 0     | UART transmit data
//!
//! UART Control Register
//!
//! Offset: +0xC
//! Reset Value: 0x0
//! Access: Write only
//!
//!  Bit(s)  | Name        | Access | Reset | Description
//! ----------------------------------------------------------
//!  0 - 26  | reserved    | -      | 0     | not used
//!  27      | enable intr | write  | 0     | enable/disable intr
//!  28 - 29 | reserved    | -      | 0     | not used
//!  30      | rst rx fifo | write  | 0     | write 1 to clear rx fifo
//!  31      | rst tx fifo | write  | 0     | write 1 to clear tx fifo
//!
//! UART Status Register
//!
//! Offset: +0x8
//! Reset Value: 0x4
//! Access: Read only
//!
//!  Bit(s)  | Name          | Access | Reset | Description
//! ----------------------------------------------------------
//!  0 - 23  | reserved      | -      | 0     | not used
//!  24      | parity err    | read   | 0     | 1 if parity error occurred
//!  25      | frame err     | read   | 0     | 1 if frame error occurred
//!  26      | overrun err   | read   | 0     | 1 if rx fifo overrun occurred
//!  27      | intr enable   | read   | 0     | indicates if interrupts are enabled or not
//!  28      | tx fifo full  | read   | 0     | 1 if tx fifo is full
//!  29      | tx fifo empty | read   | 1     | 1 if tx fifo empty
//!  30      | rx fifo full  | read   | 0     | 1 if rx fifo is full
//!  31      | rx fifo valid | read   | 0     | 1 if rx fifo contains valid data
//!
//! For the status register, the only fields we care about are the interrupts enabled,
//! tx fifo full/empty and rx fifo full/valid.  This is because the parity, frame, and
//! overrun conditions will never happen while emulating. (or at least we pretend they won't)
//!
use styx_core::errors::UnknownError;
use styx_core::prelude::*;
use styx_peripherals::uart::{IntoUartImpl, UartImpl};
use tokio::sync::broadcast;
use tracing::{debug, trace, warn};
mod hooks;

use crate::core_event_controller::Event;
use derivative::Derivative;
use std::collections::VecDeque;

const UART_BASE: u64 = 0x84000000;

/// The real UART implementation, coordinates the input and output
/// data streams, and manages the internal state of the UART peripheral.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct UartPortInner {
    interface_id: String,
    #[derivative(Debug = "ignore")]
    intr_enabled: bool,
    /// uart bytes that have come in from master but not read yet.
    buffer: VecDeque<u8>,
    miso_stream: broadcast::Sender<u8>,
    mosi_stream: broadcast::Receiver<u8>,
}

pub struct NewUartPortInner;
impl IntoUartImpl for NewUartPortInner {
    fn new(
        self,
        mosi: broadcast::Receiver<u8>,
        miso: broadcast::Sender<u8>,
        interface_id: String,
    ) -> Result<Box<dyn UartImpl>, UnknownError> {
        Ok(Box::new(UartPortInner {
            intr_enabled: false,
            buffer: Default::default(),
            miso_stream: miso,
            mosi_stream: mosi,
            interface_id,
        }))
    }
}
impl UartPortInner {
    /// Clears the internal rx fifo and clears the flag denoting valid data
    fn reset_rx_fifo(&mut self) {
        while self.mosi_stream.try_recv().is_ok() {}
    }

    /// called from within the guest write hook to the tx fifo register,
    /// this adds a byte to the broadcast channel
    pub fn guest_transmit_data(&mut self, value: u8) {
        debug!("guest transmit data {value}");

        let res = self.miso_stream.send(value);
        if res.is_err() {
            // this is okay, no one is listening :(
        }
    }

    /// called from within the guest hook to read from the uart
    /// rx fifo register
    pub fn guest_receive_data(&mut self) -> u8 {
        self.grab_bytes();

        self.buffer.pop_front().unwrap_or(0)
    }

    fn reset_state(&mut self, mmu: &mut Mmu) -> Result<(), UnknownError> {
        mmu.data().write(UART_BASE).bytes(&[
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4,
        ])?;

        self.intr_enabled = false;
        //self.inner_hal.lock().unwrap().reset();

        trace!("Uart reset_state()");

        Ok(())
    }

    fn rx_valid(&self) -> bool {
        !self.buffer.is_empty()
    }

    /// checks uart mosi for bytes and gives to buffer
    fn grab_bytes(&mut self) {
        loop {
            let res = self.mosi_stream.try_recv();
            match res {
                Ok(data) => {
                    //println!("got uart data from grpc {data:#X}");
                    self.buffer.push_back(data)
                    // there could be more data in the stream so don't break to check again
                }
                Err(broadcast::error::TryRecvError::Empty) => {
                    // no data. this is fine
                    break;
                }
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
        proc.core
            .cpu
            .mem_read_hook(
                UART_BASE,
                UART_BASE + 0xC,
                Box::new(hooks::UartHook {
                    interface_id: self.interface_id.clone(),
                }),
            )
            .unwrap();
        proc.core
            .cpu
            .mem_write_hook(
                UART_BASE,
                UART_BASE + 0xC,
                Box::new(hooks::UartHook {
                    interface_id: self.interface_id.clone(),
                }),
            )
            .unwrap();
        self.reset_state(&mut proc.core.mmu)?;
        Ok(())
    }

    // don't think we need this
    fn post_event_hook(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _event_controller: &mut dyn EventControllerImpl,
    ) -> Result<(), UnknownError> {
        trace!("UART got post_event_hook(irq:)");

        // // if we still have data in the queue, do another event
        // if !self.rx_fifo.lock().unwrap().is_empty() {
        //     if self.intr_enabled.load(Ordering::Acquire) {
        //         // now latch the event with the event controller
        //         self.event_controller
        //             .upgrade()
        //             .unwrap()
        //             .latch_event(Event::Uart.into())
        //             .unwrap();
        //     }
        //     // set flag for rx_fifo full
        //     self.rx_valid.store(true, Ordering::Release);
        // }
        Ok(())
    }

    fn irqs(&self) -> Vec<ExceptionNumber> {
        vec![Event::Uart.into()]
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
        if self.intr_enabled && self.rx_valid() {
            event_controller.latch(Event::Uart.into()).unwrap();
        }

        Ok(())
    }
}
