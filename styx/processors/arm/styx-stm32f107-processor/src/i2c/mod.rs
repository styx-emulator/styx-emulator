// SPDX-License-Identifier: BSD-2-Clause
//! An implementation of the I2C interface for the STM32F107 processor.
//!
//! The real implementation supports switching between master and slave mode, this one is always in master mode.
//!
//! I2C Interrupts:
//!
//! IRQn | Name    | Description          | Address
//! ----------------------------------------------------
//! 31   | I2C1_EV | I2C1 event interrupt | 0x0000_00BC
//! 32   | I2C1_ER | I2C1 error interrupt | 0x0000_00C0
//! 33   | I2C2_EV | I2C2 event interrupt | 0x0000_00C4
//! 34   | I2C2_ER | I2C2 error interrupt | 0x0000_00C8
//!
//! Memory Boundaries:
//! I2C1: 0x4000 5400 - 0x4000 57FF
//! I2C2: 0x4000 5800 - 0x4000 5BFF
//!
//! - registers are all 32 bits technically but all use at most the lower 16 bits
//! - reset values for all registers are 0 except TRISE which is 0x2
//!
//! Interrupts:
//!
//! Event                       | Flag     | Enable Control
//! ----------------------------------------------------------
//! Start bit sent (Master)     | SB       | ITEVFEN
//! Address sent (Master) or    |          |
//!    Address matched (Slave)  | ADDR     |
//! 10-bit header sent (Master) | ADD10    |
//! Stop received (Slave)       | STOPF    |
//! Data byte transfer finished | BTF      |
//! ----------------------------------------------------------
//! Receive buffer not empty    | RxNE     | ITEVFEN and ITBUFEN
//! Transmit buffer empty       | TxE      |
//! ----------------------------------------------------------
//! Bus error                   | BERR     | ITERREN
//! Arbitration loss (Master)   | ARLO     |
//! Acknowledge failure         | AF       |
//! Overrun/Underrun            | OVR      |
//! PEC error                   | PECERR   |
//! Timeout/Tlow error          | TIMEOUT  |
//! SMBus Alert                 | SMBALERT |
//!
use bilge::prelude::*;
use derivative::Derivative;
use getset::Getters;
use std::collections::HashSet;
use std::pin::Pin;
use std::sync::Arc;
use styx_core::prelude::*;
use styx_core::{errors::anyhow::anyhow, grpc::io, grpc::io::i2c::i2c_port_server::I2cPortServer};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::Stream;
use tonic::async_trait;
use tracing::{debug, error, warn};

mod hooks;

type I2CSend = broadcast::Sender<I2CData>;
type I2CRecv = broadcast::Receiver<I2CData>;
type I2CInnerSend = mpsc::Sender<MessageType>;
type I2CInnerRecv = mpsc::Receiver<MessageType>;

type RegisteredDevices = Arc<Mutex<HashSet<u32>>>;

/// Defines the valid states for the I2C bus
#[derive(PartialEq, Debug)]
pub enum I2CBusState {
    /// master is addressing a device
    Address,
    /// bus is idle
    Idle,
    /// master is reading from a device
    Read,
    /// master is writing to a device
    Write,
}

#[derive(Derivative)]
pub struct I2CPortInner {
    /// port number identifier
    num: u32,
    /// the base address for this port's register block
    base_addr: u64,
    /// IRQn for i2c events
    event_interrupt: ExceptionNumber,
    /// IRQn for i2c errors
    error_interrupt: ExceptionNumber,
    /// the stored I2C register state
    inner_hal: Arc<Mutex<I2CHal>>,
    /// keeps track of the current I2C bus state
    i2c_bus_state: Mutex<I2CBusState>,
    /// the actual I2C bus, where data/signals are written
    data_stream: I2CSend,
    /// unused receiver for the bus, kept in order to keep the channel open
    /// even if no devices are connected
    _data_stream_reader: I2CRecv,
    incoming: I2CInnerRecv,
    incoming_send: Option<I2CInnerSend>,
    /// the set of currently connected I2C slave devices
    registered_devices: RegisteredDevices,
    /// event interrupt enabled/disabled
    itevten: bool,
    /// error interrupt enabled/disabled
    iterren: bool,
    /// buffer interrupt enabled/disabled
    itbufen: bool,
}

impl I2CPortInner {
    pub fn new(
        port: u32,
        base_addr: u64,
        event_irqn: ExceptionNumber,
        error_irqn: ExceptionNumber,
    ) -> Self {
        let (tx, rx) = broadcast::channel(16);
        let (incoming_send, incoming_recv) = mpsc::channel(256);
        Self {
            num: port,
            base_addr,
            event_interrupt: event_irqn,
            error_interrupt: error_irqn,
            inner_hal: Default::default(),
            i2c_bus_state: Mutex::new(I2CBusState::Idle),
            data_stream: tx,
            _data_stream_reader: rx,
            incoming_send: Some(incoming_send),
            incoming: incoming_recv,
            registered_devices: Arc::new(Mutex::new(HashSet::new())),
            // interrupts are disabled by default and must be enabled via guest code
            itevten: false,
            iterren: false,
            itbufen: false,
        }
    }

    /// Generates a start condition on the bus, raises interrupts if enabled
    pub fn generate_start_cond(
        &self,
        ev: &mut dyn EventControllerImpl,
    ) -> Result<(), UnknownError> {
        {
            let mut bus_state = self.i2c_bus_state.lock().unwrap();
            *bus_state = I2CBusState::Address;
        }

        // broadcast signal on bus
        self.data_stream.send(I2CData {
            bus: self.num,
            contents: MessageType::Signal(Sig::Start),
        })?;

        // generate interrupt if ITEVFEN is set
        if self.itevten {
            ev.latch(self.event_interrupt)?;
        }
        Ok(())
    }

    /// Generates a stop condition on the bus, interrupts are only generated
    /// for stop conditions if the interface is in slave mode which is not currently supported.
    pub fn generate_stop_cond(&self) {
        *self.i2c_bus_state.lock().unwrap() = I2CBusState::Idle;

        // broadcast signal on bus
        self.data_stream
            .send(I2CData {
                bus: self.num,
                contents: MessageType::Signal(Sig::Stop),
            })
            .unwrap();
    }

    /// Put data onto the bus, sets various register flags depending on the current bus state.
    pub fn send_data(&self, data: u8) {
        debug!("sending data: {data:x}");
        let bus_state = self.i2c_bus_state.lock().unwrap();

        match *bus_state {
            I2CBusState::Address => {
                self.data_stream
                    .send(I2CData {
                        bus: self.num,
                        contents: MessageType::Data(data),
                    })
                    .unwrap();

                // clear start bit
                self.inner_hal.lock().unwrap().sr1.set_sb(false.into());
            }
            I2CBusState::Write => {
                self.data_stream
                    .send(I2CData {
                        bus: self.num,
                        contents: MessageType::Data(data),
                    })
                    .unwrap();
            }
            _ => {
                // ignore writes if we are in Idle or Read states
                debug!("\twrite ignored, not in a valid state.");
            }
        };
    }

    /// Receive an ACK signal from a slave device.  Updates bus state.
    pub fn recv_ack(&self, ev: &mut dyn EventControllerImpl) -> Result<(), UnknownError> {
        let mut bus_state = self.i2c_bus_state.lock().unwrap();
        let mut inner = self.inner_hal.lock().unwrap();

        match *bus_state {
            I2CBusState::Address => {
                let addr_byte = inner.dr.dr();
                // set ADDR flag in SR1
                if addr_byte & 1 > 0 {
                    *bus_state = I2CBusState::Read;
                } else {
                    *bus_state = I2CBusState::Write;
                    inner.sr2.set_tra(true.into());
                    inner.sr1.set_txe(true.into());
                }

                inner.sr1.set_addr(true.into());
                // generate interrupt if ITEVFEN is set
                if self.itevten {
                    ev.latch(self.event_interrupt).unwrap();
                }
            }
            I2CBusState::Write => {
                inner.sr1.set_txe(true.into());
                inner.sr1.set_btf(true.into());

                // generate interrupt if ITEVFEN and ITBUFEN are set
                if self.itevten && self.itbufen {
                    ev.latch(self.event_interrupt)?;
                }
            }
            _ => {
                // no action required for ACKs in read or idle modes
                debug!("\tACK ignored, peripheral is in Read or Idle mode.");
            }
        };
        Ok(())
    }

    /// Receive data from a slave device.
    pub fn recv_data(&self, ev: &mut dyn EventControllerImpl, data: u8) {
        let mut inner = self.inner_hal.lock().unwrap();

        inner.dr.set_dr(data);
        inner.sr1.set_rxne(true.into());

        // generate interrupt if ITEVFEN and ITBUFEN are set
        if self.itevten && self.itbufen {
            ev.latch(self.event_interrupt).unwrap();
        }
    }

    /// Called after data register is read, sends an ACK signal on the bus.
    pub fn ready_for_more_data(&self) {
        self.data_stream
            .send(I2CData {
                bus: self.num,
                contents: MessageType::Signal(Sig::Ack),
            })
            .unwrap();
    }

    /// sets up the required memory hooks
    fn register_hooks(&self, cpu: &mut dyn CpuBackend) -> Result<(), UnknownError> {
        cpu.add_hook(StyxHook::memory_write(
            self.base_addr + I2C_CR1_OFFSET,
            hooks::i2c_cr1_w_hook,
        ))?;
        cpu.add_hook(StyxHook::memory_write(
            self.base_addr + I2C_CR2_OFFSET,
            hooks::i2c_cr2_w_hook,
        ))?;
        cpu.add_hook(StyxHook::memory_write(
            self.base_addr + I2C_DR_OFFSET,
            hooks::i2c_dr_w_hook,
        ))?;

        cpu.add_hook(StyxHook::memory_read(
            self.base_addr + I2C_CR1_OFFSET,
            hooks::i2c_cr1_r_hook,
        ))?;
        cpu.add_hook(StyxHook::memory_read(
            self.base_addr + I2C_DR_OFFSET,
            hooks::i2c_dr_r_hook,
        ))?;

        cpu.add_hook(StyxHook::memory_read(
            self.base_addr + I2C_SR1_OFFSET,
            hooks::i2c_sr1_r_hook,
        ))?;
        cpu.add_hook(StyxHook::memory_read(
            self.base_addr + I2C_SR2_OFFSET,
            hooks::i2c_sr2_r_hook,
        ))?;

        Ok(())
    }

    fn reset(&mut self) -> Result<(), UnknownError> {
        self.inner_hal.lock().unwrap().reset();

        Ok(())
    }

    fn irqs(&self) -> Vec<ExceptionNumber> {
        vec![self.event_interrupt, self.error_interrupt]
    }

    fn tick(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        event_controller: &mut dyn EventControllerImpl,
    ) -> Result<(), UnknownError> {
        match self.incoming.try_recv() {
            Ok(msg) => match msg {
                MessageType::Data(data) => self.recv_data(event_controller, data),
                MessageType::Signal(sig) => match sig {
                    Sig::Ack => self.recv_ack(event_controller)?,
                    _ => return Err(anyhow!(format!("unknown signal recevied {sig:?}"))),
                },
            },
            Err(err) => match err {
                mpsc::error::TryRecvError::Empty => (),
                mpsc::error::TryRecvError::Disconnected => {
                    return Err(anyhow!("incoming recv disconnected!!"))
                }
            },
        }

        Ok(())
    }
}

pub struct I2CController {
    pub(crate) i2cs: Vec<I2CPortInner>,
}

const I2C1_BASE_ADDR: u64 = 0x4000_5400;
const I2C2_BASE_ADDR: u64 = 0x4000_5800;

const I2C1_END_ADDR: u64 = 0x4000_57FF;

const I2C1_EVENT_IRQ: ExceptionNumber = 31;
const I2C1_ERR_IRQ: ExceptionNumber = 32;
const I2C2_EVENT_IRQ: ExceptionNumber = 33;
const I2C2_ERR_IRQ: ExceptionNumber = 34;

impl I2CController {
    pub fn new() -> Self {
        Self {
            i2cs: vec![
                I2CPortInner::new(0, I2C1_BASE_ADDR, I2C1_EVENT_IRQ, I2C1_ERR_IRQ),
                I2CPortInner::new(1, I2C2_BASE_ADDR, I2C2_EVENT_IRQ, I2C2_ERR_IRQ),
            ],
        }
    }
}

impl Peripheral for I2CController {
    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        // register port hooks
        for i2c in self.i2cs.iter_mut() {
            i2c.register_hooks(proc.core.cpu.as_mut())?;
        }

        let async_i2cs = self
            .i2cs
            .iter_mut()
            .map(I2CPortAsync::from_inner)
            .collect::<Result<Vec<_>, UnknownError>>()?;

        // create inner wrapper struct that implements the service
        let service = I2cPortServer::new(I2CControllerService { i2cs: async_i2cs });

        proc.routes.add_service(service);

        Ok(())
    }

    /// Calls `reset_state` for each child i2c port
    fn reset(&mut self, _cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        for i2c in self.i2cs.iter_mut() {
            i2c.reset()?;
        }

        Ok(())
    }

    fn irqs(&self) -> Vec<ExceptionNumber> {
        self.i2cs.iter().flat_map(|x| x.irqs()).collect()
    }

    fn tick(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        event_controller: &mut dyn EventControllerImpl,
        _delta: &styx_core::prelude::Delta,
    ) -> Result<(), UnknownError> {
        for port in self.i2cs.iter_mut() {
            port.tick(cpu, mmu, event_controller)?;
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "stm32 i2c controller"
    }
}

#[derive(Debug, Error)]
#[error("Client address '{0}' already registered, duplicate device addresses are not allowed.")]
pub struct DuplicateAddress(u32);

/// Created from a [I2CPortInner] and given to the [I2CControllerService] for async communication.
pub struct I2CPortAsync {
    send: I2CSend,
    registered_devices: RegisteredDevices,
    incoming_send: I2CInnerSend,
}
impl I2CPortAsync {
    fn from_inner(inner: &mut I2CPortInner) -> Result<Self, UnknownError> {
        Ok(Self {
            send: inner.data_stream.clone(),
            registered_devices: inner.registered_devices.clone(),
            incoming_send: inner
                .incoming_send
                .take()
                .context("inner i2c port didn't have sender :/")?,
        })
    }

    /// Registers a new device address, returns a receiver stream for the bus
    fn register_client(&self, dev_addr: u32) -> Result<I2CRecv, DuplicateAddress> {
        if self.registered_devices.lock().unwrap().insert(dev_addr) {
            Ok(self.send.subscribe())
        } else {
            warn!("Attempting to register 2 I2C devices with the same address: {dev_addr}");
            Err(DuplicateAddress(dev_addr))
        }
    }

    fn send(&self, msg: MessageType) -> Result<(), UnknownError> {
        self.incoming_send
            .try_send(msg)
            .with_context(|| "could not send incoming data")
    }

    fn send_data(&self, data: u8) -> Result<(), UnknownError> {
        self.send(MessageType::Data(data))
    }

    fn send_ack(&self) -> Result<(), UnknownError> {
        self.send(MessageType::Signal(Sig::Ack))
    }
}

pub struct I2CControllerService {
    i2cs: Vec<I2CPortAsync>,
}

impl I2CControllerService {
    /// Returns the corresponding i2c port
    fn grpc_port_to_inner_port(&self, port: u32) -> &I2CPortAsync {
        &self.i2cs[port as usize]
    }
}

#[derive(Debug, Clone)]
pub struct I2CData {
    bus: u32,
    contents: MessageType,
}

#[derive(Debug, Clone)]
enum MessageType {
    Data(u8),
    Signal(Sig),
}

#[derive(Debug, Clone)]
enum Sig {
    Ack,
    Start,
    Stop,
}

impl From<Sig> for io::i2c::Signal {
    fn from(value: Sig) -> Self {
        match value {
            Sig::Ack => io::i2c::Signal {
                sig: Some(io::i2c::signal::Sig::Ack(io::i2c::Ack {})),
            },
            Sig::Start => io::i2c::Signal {
                sig: Some(io::i2c::signal::Sig::Start(io::i2c::Start {})),
            },
            Sig::Stop => io::i2c::Signal {
                sig: Some(io::i2c::signal::Sig::Stop(io::i2c::Stop {})),
            },
        }
    }
}

impl From<I2CData> for io::i2c::I2cPacket {
    fn from(value: I2CData) -> Self {
        Self {
            bus: value.bus,
            contents: match value.contents {
                MessageType::Data(d) => Some(io::i2c::i2c_packet::Contents::Data(io::i2c::Data {
                    data: d as u32,
                })),
                MessageType::Signal(s) => Some(io::i2c::i2c_packet::Contents::Sig(s.into())),
            },
        }
    }
}

/// Determines which I2C interface an address belongs to
pub fn address_to_i2c_n(address: u64) -> usize {
    if address <= I2C1_END_ADDR {
        0
    } else {
        1
    }
}

const EMPTY: io::i2c::Empty = io::i2c::Empty {};

#[async_trait]
impl io::i2c::i2c_port_server::I2cPort for I2CControllerService {
    type RegisterClientStream =
        Pin<Box<dyn Stream<Item = Result<io::i2c::I2cPacket, tonic::Status>> + Send + 'static>>;

    /// Implementation of the RPC method to register a new device.
    async fn register_client(
        &self,
        request: tonic::Request<io::i2c::I2cRegistration>,
    ) -> tonic::Result<tonic::Response<Self::RegisterClientStream>, tonic::Status> {
        let (_, _, registration) = request.into_parts();
        let bus = registration.bus;
        let dev_addr = registration.dev_address;
        let dev_name = registration.device_name;

        debug!("<gRPC> new device {dev_name}:{dev_addr:#x} registered on I2C{bus}");

        let i2c_port = self.grpc_port_to_inner_port(bus);

        let stream = i2c_port.register_client(dev_addr);

        match stream {
            Err(e) => return Err(tonic::Status::invalid_argument(e.to_string())),
            Ok(mut s) => {
                let output = async_stream::try_stream! {
                    while let Ok(i2c_data) = s.recv().await {
                        yield i2c_data.into()
                    }
                };
                // the final pinned stream that will service
                // the requested subscription
                return Ok(tonic::Response::new(
                    Box::pin(output) as Self::RegisterClientStream
                ));
            }
        };
    }

    /// RPC method to put data onto the bus.
    async fn broadcast(
        &self,
        request: tonic::Request<io::i2c::I2cPacket>,
    ) -> tonic::Result<tonic::Response<io::i2c::Empty>> {
        let (_, _, packet) = request.into_parts();
        let bus = packet.bus;
        let contents = packet.contents.unwrap();

        let i2c_port = self.grpc_port_to_inner_port(bus);

        match contents {
            io::i2c::i2c_packet::Contents::Data(d) => {
                debug!("<gRPC> I2C{} got data: {:?}", &bus, &d);
                i2c_port.send_data(d.data as u8).unwrap()
            }
            io::i2c::i2c_packet::Contents::Sig(s) => {
                debug!("<gRPC> I2C{} got signal: {:?}", &bus, &s);
                if let io::i2c::signal::Sig::Ack(_) = s.sig.unwrap() {
                    i2c_port.send_ack().unwrap();
                }
            }
        }

        Ok(tonic::Response::new(EMPTY))
    }
}

// definitions for registers.
const I2C_CR1_OFFSET: u64 = 0;
const I2C_CR2_OFFSET: u64 = 0x4;
const I2C_DR_OFFSET: u64 = 0x10;
const I2C_SR1_OFFSET: u64 = 0x14;
const I2C_SR2_OFFSET: u64 = 0x18;

#[derive(Default, Getters, Debug)]
#[getset(get = "pub")]
pub struct I2CHal {
    pub(crate) cr1: CR1,
    pub(crate) cr2: CR2,
    pub(crate) oar1: OAR1,
    pub(crate) oar2: OAR2,
    pub(crate) dr: DR,
    pub(crate) sr1: SR1,
    pub(crate) sr2: SR2,
    pub(crate) ccr: CCR,
    pub(crate) trise: TRISE,
}

impl I2CHal {
    pub fn reset(&mut self) {
        self.cr1 = CR1::from(0);
        self.cr2 = CR2::from(0);
        self.oar1 = OAR1::from(0);
        self.oar2 = OAR2::from(0);
        self.dr = DR::from(0);
        self.sr1 = SR1::from(0);
        self.sr2 = SR2::from(0);
        self.ccr = CCR::from(0);
        self.trise = TRISE::from(0);
        self.trise.set_trise(u6::new(0x2));
    }
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
/// reset value 0x0
/// offset 0x00
pub struct CR1 {
    pub pe: u1,
    pub smbus: u1,
    res2: u1,
    pub smb_type: u1,
    pub enarp: u1,
    pub enpec: u1,
    pub engc: u1,
    pub no_stretch: u1,
    pub start: u1,
    pub stop: u1,
    pub ack: u1,
    pub pos: u1,
    pub pec: u1,
    pub alert: u1,
    res1: u1,
    pub swrst: u1,
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
/// reset value 0x0
/// offset 0x04
pub struct CR2 {
    pub freq: u6,
    res2: u2,
    pub iterren: u1,
    pub itevten: u1,
    pub itbufen: u1,
    pub dmaen: u1,
    pub last: u1,
    res1: u3,
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
/// reset value 0x0
/// offset 0x08
pub struct OAR1 {
    pub add: u10,
    res1: u5,
    pub add_mode: u1,
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
/// reset value 0x0
/// offset 0x0C
pub struct OAR2 {
    pub endual: u1,
    pub add2: u7,
    res1: u8,
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
/// reset value 0x0
/// offset 0x10
pub struct DR {
    pub dr: u8,
    res1: u8,
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
/// reset value 0x0
/// offset 0x14
pub struct SR1 {
    pub sb: u1,
    pub addr: u1,
    pub btf: u1,
    pub add10: u1,
    pub stopf: u1,
    res2: u1,
    pub rxne: u1,
    pub txe: u1,
    pub berr: u1,
    pub arlo: u1,
    pub af: u1,
    pub ovr: u1,
    pub pec_err: u1,
    res1: u1,
    pub rc_w0: u1,
    pub smb_alert: u1,
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
/// reset value 0x0
/// offset 0x18
pub struct SR2 {
    pub msl: u1,
    pub busy: u1,
    pub tra: u1,
    res1: u1,
    pub gen_call: u1,
    pub smbde_fault: u1,
    pub smb_host: u1,
    pub dualf: u1,
    pub pec: u8,
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
/// reset value 0x0
/// offset 0x1C
pub struct CCR {
    pub ccr: u12,
    res1: u2,
    pub duty: u1,
    pub f_s: u1,
}

#[bitsize(16)]
#[derive(DebugBits, Default, FromBits, Clone)]
/// reset value 0x2
/// offset 0x1C
pub struct TRISE {
    pub trise: u6,
    res1: u10,
}
