// SPDX-License-Identifier: BSD-2-Clause
//! Emulates Uart controller for K21
//!
use hooks::{UartC2Hook, UartDHook, UartS1Hook};
use std::collections::VecDeque;
use std::mem::offset_of;
use styx_core::errors::UnknownError;
use styx_core::memory::Mmu;
use styx_core::prelude::{CpuBackend, ExceptionNumber};

use tokio::sync::broadcast;
use tracing::{debug, trace, warn};
// base UART type
use super::mk21f12_sys::UART_Type;

// all the mmio hooks
mod hooks;
// the inner uart state machine
mod inner;

use inner::UartHalLayer;
// interrupt numbers
use super::mk21f12_sys::{
    IRQn_UART0_ERR_IRQn, IRQn_UART0_RX_TX_IRQn, IRQn_UART1_ERR_IRQn, IRQn_UART1_RX_TX_IRQn,
    IRQn_UART2_ERR_IRQn, IRQn_UART2_RX_TX_IRQn, IRQn_UART3_ERR_IRQn, IRQn_UART3_RX_TX_IRQn,
    IRQn_UART4_ERR_IRQn, IRQn_UART4_RX_TX_IRQn, IRQn_UART5_ERR_IRQn, IRQn_UART5_RX_TX_IRQn,
};

// UART port base addresses
use super::mk21f12_sys::{UART0_BASE, UART1_BASE, UART2_BASE, UART3_BASE, UART4_BASE, UART5_BASE};

use styx_peripherals::uart::{IntoUartImpl, UartImpl, UartInterface};

pub fn get_uarts() -> Vec<UartInterface> {
    vec![
        UartInterface::new(
            "0".into(),
            UartPortBuilder::new(UART0_BASE, IRQn_UART0_ERR_IRQn, IRQn_UART0_RX_TX_IRQn),
        ),
        UartInterface::new(
            "1".into(),
            UartPortBuilder::new(UART1_BASE, IRQn_UART1_ERR_IRQn, IRQn_UART1_RX_TX_IRQn),
        ),
        UartInterface::new(
            "2".into(),
            UartPortBuilder::new(UART2_BASE, IRQn_UART2_ERR_IRQn, IRQn_UART2_RX_TX_IRQn),
        ),
        UartInterface::new(
            "3".into(),
            UartPortBuilder::new(UART3_BASE, IRQn_UART3_ERR_IRQn, IRQn_UART3_RX_TX_IRQn),
        ),
        UartInterface::new(
            "4".into(),
            UartPortBuilder::new(UART4_BASE, IRQn_UART4_ERR_IRQn, IRQn_UART4_RX_TX_IRQn),
        ),
        UartInterface::new(
            "5".into(),
            UartPortBuilder::new(UART5_BASE, IRQn_UART5_ERR_IRQn, IRQn_UART5_RX_TX_IRQn),
        ),
    ]
}

/// The real UART implementation, coordinates the input and output
/// data streams, and manages the internal state of the UART peripheral.
#[derive(Debug)]
pub struct UartPortInner {
    interface_id: String,
    base_address: u32,
    error_irqn: ExceptionNumber,
    tx_rx_irqn: ExceptionNumber,
    inner_hal: UartHalLayer,
    rx_fifo: VecDeque<u8>,
    miso_stream: broadcast::Sender<u8>,
    mosi_stream: broadcast::Receiver<u8>,
}

pub struct UartPortBuilder {
    base_address: u32,
    error_irqn: ExceptionNumber,
    tx_rx_irqn: ExceptionNumber,
}

impl UartPortBuilder {
    pub fn new(
        base_address: u32,
        error_irqn: ExceptionNumber,
        tx_rx_irqn: ExceptionNumber,
    ) -> Self {
        Self {
            base_address,
            error_irqn,
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
            error_irqn: self.error_irqn,
            tx_rx_irqn: self.tx_rx_irqn,
            inner_hal: UartHalLayer::default(),
            rx_fifo: VecDeque::default(),
            miso_stream: miso_rx,
            mosi_stream: mosi_tx,
        }))
    }
}

impl UartPortInner {
    fn reset_state(&self, mmu: &mut Mmu) -> Result<(), UnknownError> {
        // initialize uart registers S1 and SFIFO to 0xC0
        mmu.write_data((self.base_address + 0x4).into(), &[0xC0])
            .unwrap();
        mmu.write_data((self.base_address + 0x12).into(), &[0xC0])
            .unwrap();
        trace!("Uart{} .reset_state()", self.interface_id);

        Ok(())
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

        self.rx_fifo.pop_front().unwrap_or(0)
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

    #[inline]
    fn rx_valid(&self) -> bool {
        !self.rx_fifo.is_empty()
    }

    /// Connects all the MMIO registers belonging to the [`UartPortInner`]
    /// to the actual backend.
    fn register_mmio_hooks(&self, cpu: &mut dyn CpuBackend) -> Result<(), UnknownError> {
        // C2
        let c2_addr = offset_of!(UART_Type, C2) as u64 + self.base_address as u64;
        cpu.mem_write_hook(
            c2_addr,
            c2_addr,
            Box::new(UartC2Hook(self.interface_id.clone())),
        )?;

        // S1
        let s1_addr = offset_of!(UART_Type, S1) as u64 + self.base_address as u64;
        cpu.mem_write_hook(
            s1_addr,
            s1_addr,
            Box::new(UartS1Hook(self.interface_id.clone())),
        )?;
        cpu.mem_read_hook(
            s1_addr,
            s1_addr,
            Box::new(UartS1Hook(self.interface_id.clone())),
        )?;

        // D
        let d_addr = offset_of!(UART_Type, D) as u64 + self.base_address as u64;
        cpu.mem_write_hook(
            d_addr,
            d_addr,
            Box::new(UartDHook(self.interface_id.clone())),
        )?;
        cpu.mem_read_hook(
            d_addr,
            d_addr,
            Box::new(UartDHook(self.interface_id.clone())),
        )?;

        // Currently unimplemented
        // BDH
        // BDL
        // RESERVED_0
        // RESERVED_1
        // C1
        // S2
        // C3
        // MA1
        // MA2
        // C4
        // C5
        // ED
        // MODEM
        // IR
        // SFIFO
        // CFIFO
        // PFIFO
        // TWFIFO
        // TCFIFO
        // RWFIFO
        // RCFIFO
        // C7816
        // IE7816
        // IS7816
        // WN7816
        // WF7816
        // ET7816
        // TL7816
        Ok(())
    }
}

impl UartImpl for UartPortInner {
    fn init(
        &mut self,
        proc: &mut styx_core::prelude::BuildingProcessor,
    ) -> Result<(), UnknownError> {
        self.register_mmio_hooks(proc.core.cpu.as_mut())?;
        self.reset_state(&mut proc.core.mmu)?;

        Ok(())
    }

    fn post_event_hook(
        &mut self,
        _cpu: &mut dyn styx_core::prelude::CpuBackend,
        _mmu: &mut styx_core::prelude::Mmu,
        _event_controller: &mut dyn styx_core::prelude::EventControllerImpl,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    fn irqs(&self) -> Vec<styx_core::prelude::ExceptionNumber> {
        vec![self.error_irqn, self.tx_rx_irqn]
    }

    fn tick(
        &mut self,
        _cpu: &mut dyn styx_core::prelude::CpuBackend,
        _mmu: &mut styx_core::prelude::Mmu,
        event_controller: &mut dyn styx_core::prelude::EventControllerImpl,
    ) -> Result<(), UnknownError> {
        // get bytes from mosi buffer
        self.grab_bytes();

        // latch interrupt if uart data is available
        // this will latch multiple times even if no uart data arrived but uart data is available
        // ... probably not an issue :D
        if self.rx_valid() {
            // now latch the event with the event controller
            event_controller.latch(self.tx_rx_irqn).unwrap();
            self.inner_hal.s1.set_rdrf(true.into());
        }

        Ok(())
    }
}

/*
impl UartImpl for UartPortInner {

    fn post_event_hook(&self, num: EventIRQn) -> Result<(), UnknownError> {
        trace!(
            "UART{} got post_event_hook(irq: {})",
            self.interface_id,
            num
        );

        // if event is "rx / tx":
        //    check if we have more data for the guest to process, if so, relatch
        if num == self.tx_rx_irqn {
            let s1 = self.inner().s1().clone();
            let c2 = self.inner().c2().clone();

            if !self.rx_fifo.lock().unwrap().is_empty() {
                trace!(
                    "UART{} re-latching IRQ{}: rx_fifo is not empty()",
                    self.interface_id,
                    num
                );

                self.event_controller.upgrade().unwrap().latch_event(num)?;
            } else if c2.tie() && s1.tc().into() {
                trace!(
                    "C2[TIE] && S1[TC] set -> re-latching UART{} IRQ, (good -- detected cleanup irq)",
                    self.interface_id
                );

                // transmit complete, and transmit complete enable is set...fire away
                self.event_controller.upgrade().unwrap().latch_event(num)?;
            } else {
                // fifo's are now empty
                // TODO: set the FIFO empty bit
                trace!(
                    "UART{}::post_event_hook see's all fifo's empty",
                    self.interface_id
                );
            }

            // TODO: we don't handle TX post event yet
            trace!("len of RX FIFO: {:?}", self.rx_fifo.lock().unwrap().len());
        }

        // we don't handle the error case yet
        if num == self.error_irqn {
            error!("UartPortInner::post_event_hook got ERR_IRQn {}", num);
        }

        Ok(())
    }

    fn irqs(&self) -> Vec<EventIRQn> {
        vec![self.error_irqn as EventIRQn, self.tx_rx_irqn as EventIRQn]
    }

    fn init_tx_stream(&self, channel: broadcast::Sender<UartData>) {
        self.data_stream.init(channel).unwrap();
    }

    fn init_interface_id(&self, id: String) {
        self.interface_id.init(id).unwrap();
    }

    fn init_evt_controller(&self, event_controller: Weak<dyn EventController>) {
        self.event_controller.init(event_controller).unwrap()
    }

    fn receive_data(&self, data: &[u8]) {
        // Only one interrupt for each UART port can be executing at a time.
        // Dropped when function execution completes
        let _exec_lock = self.executing_interrupt.lock();

        // populate the necessary MMIO registers
        trace!("Performing RX of data: {:?}", data);

        // get the lock of the rx_fifo
        // NOTE: this is in its own context to drop the [`MutexGuard`](styx_core::sync::sync::MutexGuard)
        // as soon as we're done using it
        {
            let mut rx_fifo = self.rx_fifo.lock().unwrap();

            // add the entire message to the back
            for byte in data.iter() {
                rx_fifo.push_back(*byte);
            }
        }

        // now latch the event with the event controller
        self.event_controller
            .upgrade()
            .unwrap()
            .latch_event(self.tx_rx_irqn)
            .unwrap();
        self.inner_hal.lock().unwrap().s1.set_rdrf(true.into());
    }
}

unsafe impl Sync for UartPortInner {}
unsafe impl Send for UartPortInner {}

impl UartPortInner {
    pub fn new_arc(
        base: u32,
        error_irqn: EventIRQn,
        tx_rx_irqn: EventIRQn,
        rx_fifo_size: usize,
    ) -> Arc<Self> {
        // TODO: make a static sized queue to emulate proper fifosize
        // TODO: re-evaluate if the above is actually needed
        let mut rx_fifo = VecDeque::new();
        rx_fifo.reserve_exact(rx_fifo_size);

        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            interface_id: LateInit::default(),
            base_address: base,
            error_irqn,
            tx_rx_irqn,
            event_controller: LateInit::default(),
            inner_hal: Default::default(),
            rx_fifo: Arc::new(Mutex::new(rx_fifo)),
            data_stream: LateInit::default(),
            executing_interrupt: Mutex::new(PhantomData),
        })
    }

    /// Get a [`MutexGuard`] of the inner uart data struct
    pub fn inner(&self) -> MutexGuard<UartHalLayer> {
        let inner = self.inner_hal.lock().unwrap();
        inner
    }

    /// called from within the guest hook to read from the uart
    /// data register
    pub fn guest_receive_data(&self) -> u8 {
        let mut rx_fifo = self.rx_fifo.lock().unwrap();

        // if there's data, send it to the guest, else null byte
        rx_fifo.pop_front().unwrap_or(0)
    }

    /// called from within the guest write hook to the data register,
    /// this adds a byte to the broadcast channel
    pub fn guest_transmit_data(&self, value: u8) {
        let subscribers = self
            .data_stream
            .send(UartData {
                data: Arc::new(Box::new([value])),
                port: self.interface_id.clone(),
                is_rx: false,
            })
            .unwrap();

        trace!("Send new value to {} subscriber", subscribers);
    }
}

/// Generates the code required to tie the Read + Write callback to
/// to the backend, lots of code de-dupe
macro_rules! uart_mmio_hook {
    ($register:ident, $cpu:ident, $port:ident) => {
        let reg_start = offset_of!(UART_Type, $register) as u64 + $port.base_address as u64;

        $cpu.mem_write_hook_data(
            reg_start,
            reg_start,
            paste! {
                Box::new(hooks::[<uart_port_ $register:lower _w_hook>])
            },
            $port.me.upgrade().unwrap(),
        )
        .unwrap();
        $cpu.mem_read_hook_data(
            reg_start,
            reg_start,
            paste! {
                Box::new(hooks::[<uart_port_ $register:lower _r_hook>])
            },
            $port.me.upgrade().unwrap(),
        )
        .unwrap();
    };
}

impl UartPortInner {
    /// Connects all the MMIO registers belonging to the [`UartPortInner`]
    /// to the actual backend.
    fn register_mmio_hooks(&self, cpu: &CpuBackend) -> Result<(), StyxCpuBackendError> {
        // BDH
        uart_mmio_hook!(BDH, cpu, self);

        // BDL
        uart_mmio_hook!(BDL, cpu, self);

        // C1
        uart_mmio_hook!(C1, cpu, self);

        // C2
        uart_mmio_hook!(C2, cpu, self);

        // S1
        uart_mmio_hook!(S1, cpu, self);

        // S2
        uart_mmio_hook!(S2, cpu, self);

        // C3
        uart_mmio_hook!(C3, cpu, self);

        // D
        uart_mmio_hook!(D, cpu, self);

        // MA1
        uart_mmio_hook!(MA1, cpu, self);

        // MA2
        uart_mmio_hook!(MA2, cpu, self);

        // C4
        uart_mmio_hook!(C4, cpu, self);

        // C5
        uart_mmio_hook!(C5, cpu, self);

        // ED
        uart_mmio_hook!(ED, cpu, self);

        // MODEM
        uart_mmio_hook!(MODEM, cpu, self);

        // IR
        uart_mmio_hook!(IR, cpu, self);

        // RESERVED_0
        uart_mmio_hook!(RESERVED_0, cpu, self);

        // PFIFO
        uart_mmio_hook!(PFIFO, cpu, self);

        // CFIFO
        uart_mmio_hook!(CFIFO, cpu, self);

        // SFIFO
        uart_mmio_hook!(SFIFO, cpu, self);

        // TWFIFO
        uart_mmio_hook!(TWFIFO, cpu, self);

        // TCFIFO
        uart_mmio_hook!(TCFIFO, cpu, self);

        // RWFIFO
        uart_mmio_hook!(RWFIFO, cpu, self);

        // RCFIFO
        uart_mmio_hook!(RCFIFO, cpu, self);

        // TODO: this is currently unimplemented
        // RESERVED_1
        // C7816
        // IE7816
        // IS7816
        // WN7816
        // WF7816
        // ET7816
        // TL7816
        Ok(())
    }
}

/// Converts a provided address into a valid uart port index.
/// Panics on error.
///
/// TODO: now that we have userdata, this can become much nicer
///
/// # Examples
/// ```compile_fail
/// # use styx_machines::arm::nxp::kinetis_21::uart::address_to_uart_n;
/// assert!(address_to_uart_n(0x4006A000) == 0);
/// assert!(address_to_uart_n(0x4006A004) == 0);
/// assert!(address_to_uart_n(0x4006B010) == 1);
/// assert!(address_to_uart_n(0x400EB020) == 5);
/// ```
pub fn address_to_uart_n(address: u64) -> usize {
    let uart_size = std::mem::size_of::<UART_Type>() as u64;
    if address >= UART0_BASE as u64 && address < UART1_BASE as u64 {
        0
    } else if address < UART2_BASE as u64 {
        1
    } else if address < UART3_BASE as u64 {
        2
    } else if address < UART4_BASE as u64 {
        3
    } else if address < UART5_BASE as u64 {
        4
    } else if address <= UART5_BASE as u64 + uart_size {
        5
    } else {
        unreachable!()
    }
}

/// For the moment this is used for debugging to see if we miss any mmio
/// registers that the guest is writing to, at the moment we're ignoring
/// a couple registers so this is still here
#[allow(dead_code)]
fn uart_port_log_mem_read(_cpu: &CpuBackend, address: u64, size: u32) {
    // figure out which uart we're working with
    let uart_num = address_to_uart_n(address);
    error!(
        "(R) UART{} read size {} from {:#08X}",
        uart_num, size, address
    );
}

/// see previous comment
#[allow(dead_code)]
fn uart_port_log_mem_write(_cpu: &CpuBackend, address: u64, size: u32, data: &[u8]) {
    // figure out which uart we're working with
    let uart_num = address_to_uart_n(address);
    error!(
        "(W) UART{} write size {} to {:#08X}: {:?}",
        uart_num, size, address, data
    );
}
*/
