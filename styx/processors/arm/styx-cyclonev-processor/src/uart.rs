// SPDX-License-Identifier: BSD-2-Clause
//! Emulates Uart controller for the Cyclone V HPS.
use hooks::UartMMRHook;
use std::sync::{Arc, Mutex};
use styx_core::event_controller::{PeripheralTickCtx, RaisedIrqs};
use styx_core::prelude::*;
use styx_cyclone_v_hps_sys::{uart0, Uart0, Uart1};
use tokio::sync::broadcast;
use tracing::{debug, warn};

// base UART type
use super::altera_hps_sys::{IRQn_UART0_RX_TX_IRQn, IRQn_UART1_RX_TX_IRQn};

// all the mmio hooks
mod hooks;
mod inner;

use inner::{UartHalLayer, UartPortNumber};

use styx_peripherals::uart::{IntoUartImpl, UartImpl, UartInterface};
//
// XXX: Some features that are missing:
//         - UART reset from the Cyclone V Reset Manager.
//         - UART DMA
//         - UART non-FIFO mode

pub fn get_uarts() -> Vec<UartInterface> {
    vec![
        UartInterface::new("0".into(), UartPortBuilder::new(UartPortNumber::Zero)),
        UartInterface::new("1".into(), UartPortBuilder::new(UartPortNumber::One)),
    ]
}

pub struct UartPortInner {
    interface_id: String,
    base_address: u64,
    tx_rx_irqn: ExceptionNumber,
    pub inner_hal: UartHalLayer,

    miso_stream: broadcast::Sender<u8>,
    mosi_stream: broadcast::Receiver<u8>,
}

pub struct UartPortBuilder {
    port_num: UartPortNumber,
}

impl UartPortBuilder {
    pub fn new(port: UartPortNumber) -> Self {
        Self { port_num: port }
    }
}

impl IntoUartImpl for UartPortBuilder {
    fn new(
        self,
        mosi_tx: broadcast::Receiver<u8>,
        miso_rx: broadcast::Sender<u8>,
        interface_id: String,
    ) -> Result<Box<dyn UartImpl>, UnknownError> {
        let base: u64;
        let irqn: ExceptionNumber;
        match self.port_num {
            UartPortNumber::Zero => {
                base = Uart0::BASE as u64;
                irqn = IRQn_UART0_RX_TX_IRQn;
            }
            UartPortNumber::One => {
                base = Uart1::BASE as u64;
                irqn = IRQn_UART1_RX_TX_IRQn;
            }
        };

        let inner = UartPortInner {
            interface_id: interface_id.clone(),
            base_address: base,
            tx_rx_irqn: irqn,
            inner_hal: UartHalLayer::new(base),
            miso_stream: miso_rx,
            mosi_stream: mosi_tx,
        };
        Ok(Box::new(SharedUartPort {
            inner: Arc::new(Mutex::new(inner)),
        }))
    }
}

/// Wrapper that holds shared UART port state behind `Arc<Mutex<>>` so that
/// closure-based hooks can access it without going through `Peripherals`.
pub struct SharedUartPort {
    inner: Arc<Mutex<UartPortInner>>,
}

impl UartImpl for SharedUartPort {
    fn init(
        &mut self,
        proc: &mut styx_core::prelude::BuildingProcessor,
    ) -> Result<(), UnknownError> {
        let guard = self.inner.lock().unwrap();
        let base_address = guard.base_address;
        let interface_id = guard.interface_id.clone();
        drop(guard);

        let cpu = proc.vcpus[0].cpu.as_mut();
        cpu.mem_read_hook(
            base_address,
            base_address + std::mem::size_of::<uart0::RegisterBlock>() as u64,
            Box::new(UartMMRHook::new(
                base_address,
                interface_id.clone(),
                self.inner.clone(),
            )),
        )?;
        cpu.mem_write_hook(
            base_address,
            base_address + std::mem::size_of::<uart0::RegisterBlock>() as u64,
            Box::new(UartMMRHook::new(
                base_address,
                interface_id,
                self.inner.clone(),
            )),
        )?;

        Ok(())
    }

    fn irqs(&self) -> Vec<ExceptionNumber> {
        vec![self.inner.lock().unwrap().tx_rx_irqn]
    }

    fn tick(&mut self, _ctx: &PeripheralTickCtx<'_>) -> Result<RaisedIrqs, UnknownError> {
        let mut inner = self.inner.lock().unwrap();
        inner.grab_bytes();

        let mut raised = RaisedIrqs::none();
        let tx_rx_irqn = inner.tx_rx_irqn;
        if inner.check_generate_receive_interrupt() || inner.check_generate_transmit_interrupt() {
            raised.push(tx_rx_irqn);
        }

        Ok(raised)
    }
}

impl UartPortInner {
    /// called from within the guest write hook to the tx fifo register,
    /// this adds a byte to the broadcast channel
    pub fn guest_transmit_data(&mut self, value: u8) {
        debug!("guest transmit data {value}");

        let res = self.miso_stream.send(value);
        if res.is_err() {
            // this is okay, no one is listening :(
        }
    }

    /// checks uart mosi for bytes and gives to buffer
    pub(crate) fn grab_bytes(&mut self) {
        loop {
            let res = self.mosi_stream.try_recv();
            match res {
                Ok(data) => self.inner_hal.fifo.rx_put(data),
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

    /// Update the UART's interrupt state from the receive FIFO and
    /// return `true` if an interrupt should be raised.
    fn check_generate_receive_interrupt(&mut self) -> bool {
        // For FIFO mode, check the Receive FIFO Trigger Level.
        // FIXME: We should just be checking if we've reached the RX trigger level, but we can't
        // rely on that since we do not yet have a mechanism for generating character timeouts.
        if !self.inner_hal.fifo.rx_is_empty() {
            // Set the interrupt so the guest can see which interrupt fired upon reading the
            // interrupt identification register.
            self.inner_hal
                .interrupt_control
                .int_rx_data_aval_and_char_timeout
                .set();

            if !self.inner_hal.fifo.rx_trigger_level_reached() {
                // We fake a character timeout, since we don't yet have a timer.
                self.inner_hal.interrupt_control.char_timeout = true;
            }

            if self
                .inner_hal
                .interrupt_control
                .int_rx_data_aval_and_char_timeout
                .triggered()
            {
                return true;
            }
        }
        false
    }

    /// Update the UART's interrupt state from the transmit FIFO and
    /// return `true` if an interrupt should be raised.
    fn check_generate_transmit_interrupt(&mut self) -> bool {
        // For FIFO mode, check the empty threshold.
        if self.inner_hal.fifo.tx_empty_threshold_reached() {
            // Set the interrupt so the guest can see which interrupt fired upon reading the
            // interrupt identification register.
            self.inner_hal.interrupt_control.int_tx_holding_empty.set();

            if self
                .inner_hal
                .interrupt_control
                .int_tx_holding_empty
                .triggered()
            {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::inner::UART_REG_BLOCK_SIZE;
    use styx_cyclone_v_hps_sys::generic::FromBytes;
    use styx_cyclone_v_hps_sys::uart0;

    #[test]
    fn does_it_work() {
        let init_bytes: [u8; UART_REG_BLOCK_SIZE] = [0u8; UART_REG_BLOCK_SIZE];
        unsafe {
            let regs: uart0::RegisterBlock = uart0::RegisterBlock::from_bytes(&init_bytes).unwrap();

            assert!(!regs.lsr().read().dr().bit());
            regs.lsr().sys_modify(|_, w| w.dr().set_bit());
            assert!(regs.lsr().read().dr().bit());
        }
    }
}
