// SPDX-License-Identifier: BSD-2-Clause
//!
//! memory ranges for each SPI port:
//!
//! SPI2 : 0x4000 3800 - 0x4000 3BFF
//! SPI3 : 0x4000 3C00 - 0x4000 3FFF
//! SPI1 : 0x4001 3000 - 0x4001 33FF
//!
use bilge::prelude::*;
use derivative::Derivative;
use getset::Getters;
use std::collections::VecDeque;
use std::pin::Pin;
use styx_core::grpc::io;
use styx_core::prelude::*;
use thiserror::Error;
use tokio::sync::broadcast;
use tokio_stream::Stream;
use tonic::async_trait;
use tracing::{debug, error, warn};

mod hooks;

const SPI2_END: u64 = 0x4000_3BFF;
const SPI3_END: u64 = 0x4000_3FFF;

type SPIOutboundSend = broadcast::Sender<SPIData>;
type SPIOutboundRecv = broadcast::Receiver<SPIData>;

/// Converts an address into the SPI port that it belongs to, as zero-indexed number.
/// SPI1 has a higher address block compared to SPI2 and SPI3 which is why this function looks wrong.
fn addr_to_spi_port(addr: u64) -> usize {
    if addr <= SPI2_END {
        1
    } else if addr <= SPI3_END {
        2
    } else {
        0
    }
}

#[derive(Clone, Debug)]
pub struct SPIData {
    port: usize,
    contents: SPIPacketContents,
}

#[derive(Clone, Debug)]
enum SPIPacketContents {
    ChipSelect(bool),
    Data(Box<[u8]>),
}

impl From<SPIData> for io::spi::Packet {
    fn from(value: SPIData) -> Self {
        Self {
            port: value.port as u32,
            contents: Some(match value.contents {
                SPIPacketContents::ChipSelect(state) => {
                    io::spi::packet::Contents::ChipSelect(io::spi::ChipSelect { state })
                }
                SPIPacketContents::Data(data) => io::spi::packet::Contents::Data(io::spi::Data {
                    data: data.to_vec(),
                }),
            }),
        }
    }
}

#[derive(Derivative)]
pub struct SPIPortInner {
    /// port number identifier
    num: u32,
    /// the base address for this port's register block
    base_addr: u64,
    /// the stored SPI register state
    inner_hal: SPIHal,
    /// IRQn for SPI interrupts
    event_irqn: ExceptionNumber,
    /// supports 8 bit or 16 bit data frame size
    byte_frame_size: bool,
    /// a queue for received data
    rx_fifo: Arc<Mutex<VecDeque<u8>>>,
    /// the sent data stream
    outbound_spi: SPIOutboundSend,
    /// held to keep the stream open, not actually used anywhere
    _data_stream_reader: SPIOutboundRecv,

    /// transmit buffer empty interrupt enable
    txeie: bool,
    /// receive buffer not empty interrupt enable
    rxneie: bool,
    /// error interrupt enable
    errie: bool,
    /// slave select line
    selected: bool,
}

const RX_TX_FIFO_SIZE: usize = 32;

impl SPIPortInner {
    pub fn new(num: u32, base_addr: u64, event_irqn: ExceptionNumber) -> Self {
        let (tx, rx) = broadcast::channel(16);
        Self {
            num,
            base_addr,
            inner_hal: Default::default(),
            event_irqn,
            byte_frame_size: true,
            rx_fifo: Arc::new(Mutex::new(VecDeque::with_capacity(RX_TX_FIFO_SIZE))),
            outbound_spi: tx,
            _data_stream_reader: rx,
            txeie: false,
            rxneie: false,
            errie: false,
            selected: false,
        }
    }

    pub fn slave_select(&mut self, state: bool) {
        warn!("[SPI{}] slave select: {state}", self.num);

        if self.selected != state {
            self.selected = state;
            // state changed, send signal and clear buffer
            self.rx_fifo.lock().unwrap().clear();
            self.outbound_spi
                .send(SPIData {
                    port: self.num as usize,
                    contents: SPIPacketContents::ChipSelect(state),
                })
                .unwrap();
        }
    }

    pub fn transmit_data(&mut self, ev: &mut dyn EventControllerImpl, value: u8) {
        debug!("[SPI{}] sending data: {value:08b}", self.num);
        self.outbound_spi
            .send(SPIData {
                contents: SPIPacketContents::Data(Box::new([value])),
                port: self.num as usize,
            })
            .unwrap();

        // trigger a TX buffer empty interrupt event, if enabled
        if self.txeie {
            ev.latch(self.event_irqn).unwrap();
        }

        // set TXE flag
        self.inner_hal.sr.set_txe(true.into());
    }

    pub fn receive_data(
        &mut self,
        event_controller: &mut dyn EventControllerImpl,
    ) -> Result<(), UnknownError> {
        let q = self.rx_fifo.lock().unwrap();
        if q.is_empty() {
            return Ok(());
        }
        if !self.selected {
            // ignore data from device if we haven't selected it
            self.inner_hal.sr.set_rxne(false.into());
            return Ok(());
        }

        // trigger a RX buffer full interrupt event, if enabled
        if self.rxneie {
            event_controller.latch(self.event_irqn).unwrap();
        }
        // set RXNE flag
        self.inner_hal.sr.set_rxne(true.into());
        Ok(())
    }

    pub fn read_data(&mut self) -> u8 {
        let mut q = self.rx_fifo.lock().unwrap();
        // if no data is available, then return 0
        let d = q.pop_front().unwrap_or(0);

        if q.len() == 0 {
            // clear RXNE flag if we just pulled the last value from the queue
            self.inner_hal.sr.set_rxne(false.into());
        }
        d
    }

    fn tick(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        event_controller: &mut dyn EventControllerImpl,
    ) -> Result<(), UnknownError> {
        self.receive_data(event_controller)?;
        Ok(())
    }
}

// register offsets within each SPI port memory block
const SPI_CR1_OFFSET: u64 = 0x0;
const SPI_CR2_OFFSET: u64 = 0x4;
const SPI_SR_OFFSET: u64 = 0x8;
const SPI_DR_OFFSET: u64 = 0xC;

impl SPIPortInner {
    /// set initial register state
    fn reset_state(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
    ) -> Result<(), UnknownError> {
        // reset the inner register state
        self.inner_hal.reset();
        Ok(())
    }

    /// sets up the required memory hooks
    fn init(&self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        let cpu = proc.core.cpu.as_mut();

        cpu.add_hook(StyxHook::memory_write(
            self.base_addr + SPI_CR1_OFFSET,
            hooks::spi_cr1_w_hook,
        ))?;
        cpu.add_hook(StyxHook::memory_write(
            self.base_addr + SPI_CR2_OFFSET,
            hooks::spi_cr2_w_hook,
        ))?;
        cpu.add_hook(StyxHook::memory_write(
            self.base_addr + SPI_DR_OFFSET,
            hooks::spi_dr_w_hook,
        ))?;
        cpu.add_hook(StyxHook::memory_read(
            self.base_addr + SPI_DR_OFFSET,
            hooks::spi_dr_r_hook,
        ))?;
        cpu.add_hook(StyxHook::memory_read(
            self.base_addr + SPI_SR_OFFSET,
            hooks::spi_sr_r_hook,
        ))?;

        Ok(())
    }

    /// Retrieves the IRQs belonging to this [`SPIPortInner`]
    fn irqs(&self) -> Vec<ExceptionNumber> {
        vec![self.event_irqn]
    }
}

#[derive(Debug, Error)]
#[error("port {0} does not exist")]
pub struct InvalidPortError(u32);

pub struct SPIController {
    pub(crate) spi_ports: Vec<SPIPortInner>,
}

// base address of each SPI port memory region
const SPI1_BASE_ADDR: u64 = 0x4001_3000;
const SPI2_BASE_ADDR: u64 = 0x4000_3800;
const SPI3_BASE_ADDR: u64 = 0x4000_3C00;

// IRQn for each SPI port
const SPI1_EVENT_IRQN: ExceptionNumber = 35;
const SPI2_EVENT_IRQN: ExceptionNumber = 36;
const SPI3_EVENT_IRQN: ExceptionNumber = 51;

impl SPIController {
    pub fn new() -> Self {
        SPIController {
            spi_ports: vec![
                SPIPortInner::new(1, SPI2_BASE_ADDR, SPI2_EVENT_IRQN),
                SPIPortInner::new(2, SPI3_BASE_ADDR, SPI3_EVENT_IRQN),
                SPIPortInner::new(0, SPI1_BASE_ADDR, SPI1_EVENT_IRQN),
            ],
        }
    }
}

impl Peripheral for SPIController {
    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        for spi in self.spi_ports.iter() {
            spi.init(proc)?;
        }

        let async_spis = self
            .spi_ports
            .iter_mut()
            .map(SpiPortAsync::from_inner)
            .collect::<Result<Vec<_>, UnknownError>>()?;
        // create inner wrapper struct that implements the service
        let service = io::spi::spi_port_server::SpiPortServer::new(SPIControllerService {
            spi_ports: async_spis,
        });
        proc.routes.add_service(service);

        Ok(())
    }

    fn reset(&mut self, cpu: &mut dyn CpuBackend, mmu: &mut Mmu) -> Result<(), UnknownError> {
        for spi in self.spi_ports.iter_mut() {
            spi.reset_state(cpu, mmu)?;
        }

        Ok(())
    }

    fn irqs(&self) -> Vec<ExceptionNumber> {
        self.spi_ports.iter().flat_map(|x| x.irqs()).collect()
    }

    fn name(&self) -> &str {
        "stm32 spi controller"
    }

    fn tick(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        event_controller: &mut dyn EventControllerImpl,
        _delta: &styx_core::executor::Delta,
    ) -> Result<(), UnknownError> {
        for spi in self.spi_ports.iter_mut() {
            spi.tick(cpu, mmu, event_controller)?;
        }
        Ok(())
    }
}

/// Created from a [SPIPortInner] and given to the [SPIControllerService] for async communication.
pub struct SpiPortAsync {
    inbound_send: Arc<Mutex<VecDeque<u8>>>,
    outbound_send: SPIOutboundSend,
}
impl SpiPortAsync {
    fn from_inner(inner: &mut SPIPortInner) -> Result<Self, UnknownError> {
        Ok(Self {
            inbound_send: inner.rx_fifo.clone(),
            outbound_send: inner.outbound_spi.clone(),
        })
    }

    fn receive_data(&self, data: Vec<u8>) -> Result<(), UnknownError> {
        for d in data {
            self.inbound_send.lock().unwrap().push_back(d);
        }

        Ok(())
    }
}

pub struct SPIControllerService {
    spi_ports: Vec<SpiPortAsync>,
}

impl SPIControllerService {
    /// Returns the corresponding spi port
    fn grpc_port_to_inner_port(&self, port: u32) -> Result<&SpiPortAsync, InvalidPortError> {
        self.spi_ports
            .get(port as usize)
            .ok_or(InvalidPortError(port))
    }
}

#[async_trait]
impl io::spi::spi_port_server::SpiPort for SPIControllerService {
    type SubscribeStream =
        Pin<Box<dyn Stream<Item = Result<io::spi::Packet, tonic::Status>> + Send + 'static>>;

    async fn subscribe(
        &self,
        request: tonic::Request<io::spi::PortRequest>,
    ) -> Result<tonic::Response<Self::SubscribeStream>, tonic::Status> {
        let (_, _, subscribe_request) = request.into_parts();
        let port = subscribe_request.port;
        let dev_name = subscribe_request.device_name;

        debug!(
            "<gRPC> SPI port {} is being subscribed to by {}",
            port, dev_name,
        );

        match self.grpc_port_to_inner_port(port) {
            // Error case, return failure
            Err(_) => Err(tonic::Status::invalid_argument("Invalid SPI port")),

            Ok(p) => {
                let mut stream = p.outbound_send.subscribe();

                let output = async_stream::try_stream! {
                    // get the next `SPIData` and convert it into a
                    // `io::spi::Data`
                    while let Ok(spi_data) = stream.recv().await {
                        // send the data
                        yield spi_data.into()
                    }
                };

                // the final pinned stream that will service
                // the requested subscription
                Ok(tonic::Response::new(
                    Box::pin(output) as Self::SubscribeStream
                ))
            }
        }
    }

    async fn receive(
        &self,
        request: tonic::Request<io::spi::Packet>,
    ) -> tonic::Result<tonic::Response<io::spi::Empty>> {
        let (_, _, req) = request.into_parts();
        let port = req.port;
        let contents = req.contents.unwrap();

        warn!("<gRPC> SPI port {} received data: {:?}", port, contents,);

        // pass the data through to the inner port
        match self.grpc_port_to_inner_port(port) {
            // Error case, return failure
            Err(_) => Err(tonic::Status::invalid_argument("Invalid SPI port")),
            // we were able to find the port they wanted to subscribe to,
            // so now we're going to send the bytes to the desired UART port
            Ok(p) => {
                match contents {
                    io::spi::packet::Contents::ChipSelect(_) => {
                        // this isn't needed until we have slave mode implemented for the SPI interface.
                        // slave devices can't pull the select line high or low
                    }
                    io::spi::packet::Contents::Data(d) => {
                        p.receive_data(d.data).unwrap();
                    }
                }
                Ok(tonic::Response::new(io::spi::Empty {}))
            }
        }
    }
}

#[derive(Default, Getters, Debug)]
#[getset(get = "pub")]
pub struct SPIHal {
    pub(crate) cr1: CR1,
    pub(crate) cr2: CR2,
    pub(crate) sr: SR,
    pub(crate) dr: DR,
    pub(crate) crcpr: CRCPR,
    pub(crate) rxcrcr: RXCRCR,
    pub(crate) txcrcr: TXCRCR,
}

impl SPIHal {
    pub fn reset(&mut self) {
        self.cr1 = CR1::from(0);
        self.cr2 = CR2::from(0);
        self.sr = SR::from(0x2);
        self.dr = DR::from(0);
        self.crcpr = CRCPR::from(0x7);
        self.rxcrcr = RXCRCR::from(0);
        self.txcrcr = TXCRCR::from(0);
    }
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
// offset: 0x0
// reset: 0x0000
pub struct CR1 {
    pub cpha: u1,
    pub cpol: u1,
    pub mstr: u1,
    pub br: u3,
    pub spe: u1,
    pub lsb_first: u1,
    pub ssi: u1,
    pub ssm: u1,
    pub rx_only: u1,
    pub dff: u1,
    pub crc_next: u1,
    pub crc_en: u1,
    pub bidioe: u1,
    pub bidi_mode: u1,
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
// offset: 0x04
// reset: 0x0000
pub struct CR2 {
    pub rxdmaen: u1,
    pub txdmaen: u1,
    pub ssoe: u1,
    res1: u2,
    pub errie: u1,
    pub rxneie: u1,
    pub txeie: u1,
    res2: u8,
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
// offset: 0x08
// reset: 0x0002
pub struct SR {
    pub rxne: u1,
    pub txe: u1,
    pub chside: u1,
    pub udr: u1,
    pub crc_err: u1,
    pub modf: u1,
    pub ovr: u1,
    pub bsy: u1,
    res: u8,
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
// offset: 0x0C
// reset: 0x0000
pub struct DR {
    dr: u16,
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
// offset: 0x10
// reset: 0x0007
pub struct CRCPR {
    crcpoly: u16,
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
// offset: 0x14
// reset: 0x0000
pub struct RXCRCR {
    rxcrc: u16,
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
// offset: 0x18
// reset: 0x0000
pub struct TXCRCR {
    txcrc: u16,
}

#[cfg(test)]
mod tests {
    use super::SPIHal;

    #[test]
    fn test_reset() {
        let mut hal = SPIHal::default();
        hal.reset();

        assert_eq!(hal.crcpr.crcpoly(), 0x7);
        assert_eq!(hal.sr.txe(), true.into());
    }
}
