// SPDX-License-Identifier: BSD-2-Clause
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
use styx_core::event_controller::{PeripheralTickCtx, RaisedIrqs};
use styx_core::prelude::*;
use styx_peripherals::uart::{IntoUartImpl, UartImpl};
use tokio::sync::broadcast;
use tracing::{debug, trace, warn};
mod hooks;

use crate::core_event_controller::Event;
use derivative::Derivative;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

const UART_BASE: u64 = 0x84000000;

/// The real UART implementation, coordinates the input and output
/// data streams, and manages the internal state of the UART peripheral.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct UartPortInner {
    #[derivative(Debug = "ignore")]
    intr_enabled: bool,
    /// uart bytes that have come in from master but not read yet.
    buffer: VecDeque<u8>,
    miso_stream: broadcast::Sender<u8>,
    mosi_stream: broadcast::Receiver<u8>,
}

/// Shared handle to the [`UartPortInner`] state.
///
/// State is shared via this handle: the peripheral's [`UartImpl::tick`] and the
/// memory-mapped register hooks each hold a clone of the same `Arc`.
#[derive(Clone)]
pub struct UartPort {
    inner: Arc<Mutex<UartPortInner>>,
}

pub struct NewUartPortInner;
impl IntoUartImpl for NewUartPortInner {
    fn new(
        self,
        mosi: broadcast::Receiver<u8>,
        miso: broadcast::Sender<u8>,
        _interface_id: String,
    ) -> Result<Box<dyn UartImpl>, UnknownError> {
        Ok(Box::new(UartPort {
            inner: Arc::new(Mutex::new(UartPortInner {
                intr_enabled: false,
                buffer: Default::default(),
                miso_stream: miso,
                mosi_stream: mosi,
            })),
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
impl UartImpl for UartPort {
    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        proc.vcpus[0]
            .cpu
            .mem_read_hook(
                UART_BASE,
                UART_BASE + 0xC,
                Box::new(hooks::UartHook {
                    inner: self.inner.clone(),
                }),
            )
            .unwrap();
        proc.vcpus[0]
            .cpu
            .mem_write_hook(
                UART_BASE,
                UART_BASE + 0xC,
                Box::new(hooks::UartHook {
                    inner: self.inner.clone(),
                }),
            )
            .unwrap();
        self.inner
            .lock()
            .unwrap()
            .reset_state(&mut proc.vcpus[0].mmu)?;
        Ok(())
    }

    fn irqs(&self) -> Vec<ExceptionNumber> {
        vec![Event::Uart.into()]
    }

    fn tick(&mut self, _ctx: &PeripheralTickCtx<'_>) -> Result<RaisedIrqs, UnknownError> {
        let mut inner = self.inner.lock().unwrap();

        // get bytes from mosi buffer
        inner.grab_bytes();

        // raise interrupt if uart data is available
        // this will raise multiple times even if no uart data arrived but uart data is available
        // ... probably not an issue :D
        let mut raised = RaisedIrqs::none();
        if inner.intr_enabled && inner.rx_valid() {
            raised.push(Event::Uart.into());
        }

        Ok(raised)
    }
}
