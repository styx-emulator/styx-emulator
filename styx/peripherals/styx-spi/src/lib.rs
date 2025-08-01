// SPDX-License-Identifier: BSD-2-Clause
use as_any::{AsAny, Downcast};
use derivative::Derivative;
use std::any::TypeId;
use std::pin::Pin;
use styx_core::grpc::io;
use styx_core::grpc::io::spi::{
    Empty, MasterChipSelectPacket, MasterPacket, PortRequest, SlaveChipSelectPacket, SlavePacket,
};
use styx_core::prelude::*;
use thiserror::Error;
use tokio::sync::broadcast;
use tokio_stream::Stream;
use tonic::async_trait;
use tracing::error;

pub trait IntoSpiImp {
    #[allow(clippy::too_many_arguments)]
    fn new_spi_impl(
        self,

        as_master_csel: broadcast::Sender<MasterChipSelectPacket>,
        as_master_mosi: broadcast::Sender<MasterPacket>,
        as_master_miso: broadcast::Receiver<MasterPacket>,

        as_slave_csel: broadcast::Receiver<SlaveChipSelectPacket>,
        as_slave_mosi: broadcast::Receiver<SlavePacket>,
        as_slave_miso: broadcast::Sender<SlavePacket>,

        port_id: u32,
    ) -> Result<Box<dyn SpiImpl>, UnknownError>;
}

pub trait SpiImpl: AsAny + Send {
    /// Registers the memory mapped hooks needed for use by this peripheral.
    fn init(&mut self, _proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        Ok(())
    }

    /// Top half pre-event hook for peripherals to implement and
    /// handle accordingly.
    fn pre_event_hook(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _event_controller: &mut dyn EventControllerImpl,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    /// Top half post-event hook for peripherals to implement and
    /// handle accordingly.
    ///
    /// not sure if we need this?
    fn post_event_hook(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _event_controller: &mut dyn EventControllerImpl,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    /// Returns all of the IRQs that belong to this specific interface
    fn irqs(&self) -> Vec<ExceptionNumber> {
        vec![]
    }

    /// Called every tick for updates.
    fn tick(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _event_controller: &mut dyn EventControllerImpl,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    fn reset(&mut self, _cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        Ok(())
    }
}

/// Holds the clones of channels of a SpiPort so that an SpiService can do async comms.
pub struct SpiPortChannelContainer {
    pub port_id: u32,

    from_master_csel: broadcast::Receiver<MasterChipSelectPacket>,
    from_master_mosi: broadcast::Receiver<MasterPacket>,
    to_master_miso: broadcast::Sender<MasterPacket>,

    to_slave_csel: broadcast::Sender<SlaveChipSelectPacket>,
    to_slave_mosi: broadcast::Sender<SlavePacket>,
    from_slave_miso: broadcast::Receiver<SlavePacket>,
}

/// A generic Spi interface
#[derive(Derivative)]
#[derivative(Debug)]
pub struct SpiPort {
    pub port_id: u32,
    #[derivative(Debug = "ignore")]
    pub inner: Box<dyn SpiImpl>,

    from_master_csel: broadcast::Sender<MasterChipSelectPacket>,
    from_master_mosi: broadcast::Sender<MasterPacket>,
    to_master_miso: broadcast::Sender<MasterPacket>,

    to_slave_csel: broadcast::Sender<SlaveChipSelectPacket>,
    to_slave_mosi: broadcast::Sender<SlavePacket>,
    from_slave_miso: broadcast::Sender<SlavePacket>,
}

impl SpiPort {
    pub fn new(port_id: u32, spi_impl: impl IntoSpiImp) -> Self {
        let (m_csel_tx, _) = broadcast::channel(16);
        let (m_mosi_tx, _) = broadcast::channel(32);
        let (m_miso_tx, m_miso_rx) = broadcast::channel(32);

        let (s_csel_tx, s_csel_rx) = broadcast::channel(16);
        let (s_mosi_tx, s_mosi_rx) = broadcast::channel(32);
        let (s_miso_tx, _) = broadcast::channel(32);

        let inner = spi_impl
            .new_spi_impl(
                m_csel_tx.clone(),
                m_mosi_tx.clone(),
                m_miso_rx,
                s_csel_rx,
                s_mosi_rx,
                s_miso_tx.clone(),
                port_id,
            )
            .unwrap();

        Self {
            port_id,
            inner,
            from_master_csel: m_csel_tx,
            from_master_mosi: m_mosi_tx,
            to_master_miso: m_miso_tx,
            to_slave_csel: s_csel_tx,
            to_slave_mosi: s_mosi_tx,
            from_slave_miso: s_miso_tx,
        }
    }

    pub fn channel_container(&self) -> SpiPortChannelContainer {
        SpiPortChannelContainer {
            port_id: self.port_id,
            from_master_csel: self.from_master_csel.subscribe(),
            from_master_mosi: self.from_master_mosi.subscribe(),
            to_master_miso: self.to_master_miso.clone(),
            to_slave_csel: self.to_slave_csel.clone(),
            to_slave_mosi: self.to_slave_mosi.clone(),
            from_slave_miso: self.from_slave_miso.subscribe(),
        }
    }
}

pub struct SPIController {
    pub(crate) spi_ports: Vec<SpiPort>,
}

impl SPIController {
    pub fn new(ports: Vec<SpiPort>) -> Self {
        SPIController { spi_ports: ports }
    }

    pub fn get<T: SpiImpl + 'static>(&mut self, id: u32) -> Option<&mut T> {
        self.spi_ports.iter_mut().find_map(|i| {
            if i.port_id == id {
                i.inner.as_mut().downcast_mut::<T>()
            } else {
                None
            }
        })
    }

    /// [`Self::get()`] but we convenient error context.
    pub fn try_get<T: SpiImpl + 'static>(&mut self, id: u32) -> Result<&mut T, UnknownError> {
        self.get(id).with_context(|| {
            format!(
                "could not get uart interface with id '{id}' and type '{:?}'",
                TypeId::of::<T>()
            )
        })
    }
}

impl Peripheral for SPIController {
    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        for spi in self.spi_ports.iter_mut() {
            spi.inner.init(proc)?;
        }

        let channels: Vec<SpiPortChannelContainer> = self
            .spi_ports
            .iter()
            .map(SpiPort::channel_container)
            .collect();
        // create inner wrapper struct that implements the service
        let service = io::spi::spi_port_server::SpiPortServer::new(SPIControllerService {
            spi_ports: channels,
        });
        proc.routes.add_service(service);

        Ok(())
    }

    fn reset(&mut self, cpu: &mut dyn CpuBackend, mmu: &mut Mmu) -> Result<(), UnknownError> {
        for spi in self.spi_ports.iter_mut() {
            spi.inner.reset(cpu, mmu)?;
        }

        Ok(())
    }

    fn irqs(&self) -> Vec<ExceptionNumber> {
        self.spi_ports.iter().flat_map(|x| x.inner.irqs()).collect()
    }

    fn name(&self) -> &str {
        "spi controller"
    }

    fn tick(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        event_controller: &mut dyn EventControllerImpl,
        _delta: &styx_core::executor::Delta,
    ) -> Result<(), UnknownError> {
        for spi in self.spi_ports.iter_mut() {
            spi.inner.tick(cpu, mmu, event_controller)?;
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
#[error("port {0} does not exist")]
pub struct InvalidPortError(u32);

impl From<InvalidPortError> for tonic::Status {
    fn from(value: InvalidPortError) -> Self {
        tonic::Status::invalid_argument(format!("Invalid SPI port {}", value.0))
    }
}

pub struct SPIControllerService {
    spi_ports: Vec<SpiPortChannelContainer>,
}

impl SPIControllerService {
    /// Returns the corresponding spi port.
    fn grpc_port_to_inner_port(
        &self,
        port: u32,
    ) -> Result<&SpiPortChannelContainer, InvalidPortError> {
        self.spi_ports
            .iter()
            .find(|p| p.port_id == port)
            .ok_or(InvalidPortError(port))
    }
}

type SubscribeStream<T> = Pin<Box<dyn Stream<Item = Result<T, tonic::Status>> + Send + 'static>>;

#[async_trait]
impl io::spi::spi_port_server::SpiPort for SPIControllerService {
    type MasterChipSelectSubscribeStream = SubscribeStream<MasterChipSelectPacket>;
    type MasterSubscribeStream = SubscribeStream<MasterPacket>;
    type SlaveSubscribeStream = SubscribeStream<SlavePacket>;

    // =======
    // CS WIRE
    // =======
    async fn slave_chip_select_receive(
        &self,
        request: tonic::Request<SlaveChipSelectPacket>,
    ) -> Result<tonic::Response<Empty>, tonic::Status> {
        let (_, _, req) = request.into_parts();
        let port = &req.port;
        let contents = &req.chip_select;

        log::trace!(
            "<gRPC> SPI port {} slave csel received data: {:?}",
            port,
            contents
        );

        let port = self.grpc_port_to_inner_port(*port)?;
        // we were able to find the port they wanted to subscribe to,
        // so now we're going to send the bytes to the desired UART port
        port.to_slave_csel.send(req).unwrap();
        Ok(tonic::Response::new(Empty {}))
    }

    async fn master_chip_select_subscribe(
        &self,
        request: tonic::Request<PortRequest>,
    ) -> Result<tonic::Response<Self::MasterChipSelectSubscribeStream>, tonic::Status> {
        let (_, _, subscribe_request) = request.into_parts();
        let port = subscribe_request.port;
        let dev_name = subscribe_request.device_name;

        log::trace!(
            "<gRPC> SPI port {} master csel is being subscribed to by {}",
            port,
            dev_name,
        );

        let port = self.grpc_port_to_inner_port(port)?;
        let mut stream = port.from_master_csel.resubscribe();

        let output = async_stream::try_stream! {
            // get the next `SPIData` and convert it into a
            // `io::spi::Data`
            while let Ok(spi_data) = stream.recv().await {
                // send the data
                yield spi_data
            }
        };

        // the final pinned stream that will service
        // the requested subscription
        Ok(tonic::Response::new(
            Box::pin(output) as Self::MasterChipSelectSubscribeStream
        ))
    }

    // =========
    // MOSI WIRE
    // =========
    async fn slave_receive(
        &self,
        request: tonic::Request<SlavePacket>,
    ) -> Result<tonic::Response<Empty>, tonic::Status> {
        let (_, _, req) = request.into_parts();
        let port = &req.port;
        let contents = &req.data;

        log::trace!(
            "<gRPC> SPI port {} slave mosi received data: {:?}",
            port,
            contents
        );

        let port = self.grpc_port_to_inner_port(*port)?;
        // we were able to find the port they wanted to subscribe to,
        // so now we're going to send the bytes to the desired UART port
        port.to_slave_mosi.send(req).unwrap();
        Ok(tonic::Response::new(Empty {}))
    }

    async fn master_subscribe(
        &self,
        request: tonic::Request<PortRequest>,
    ) -> Result<tonic::Response<Self::MasterSubscribeStream>, tonic::Status> {
        let (_, _, subscribe_request) = request.into_parts();
        let port = subscribe_request.port;
        let dev_name = subscribe_request.device_name;

        log::trace!(
            "<gRPC> SPI port {} master mosi is being subscribed to by {}",
            port,
            dev_name,
        );

        let port = self.grpc_port_to_inner_port(port)?;
        let mut stream = port.from_master_mosi.resubscribe();

        let output = async_stream::try_stream! {
            // get the next `SPIData` and convert it into a
            // `io::spi::Data`
            while let Ok(spi_data) = stream.recv().await {
                // send the data
                yield spi_data
            }
        };

        // the final pinned stream that will service
        // the requested subscription
        Ok(tonic::Response::new(
            Box::pin(output) as Self::MasterSubscribeStream
        ))
    }

    // =========
    // MISO WIRE
    // =========

    async fn slave_subscribe(
        &self,
        request: tonic::Request<PortRequest>,
    ) -> Result<tonic::Response<Self::SlaveSubscribeStream>, tonic::Status> {
        let (_, _, subscribe_request) = request.into_parts();
        let port = subscribe_request.port;
        let dev_name = subscribe_request.device_name;

        log::trace!(
            "<gRPC> SPI port {} slave miso is being subscribed to by {}",
            port,
            dev_name,
        );

        let port = self.grpc_port_to_inner_port(port)?;
        let mut stream = port.from_slave_miso.resubscribe();

        let output = async_stream::try_stream! {
            // get the next `SPIData` and convert it into a
            // `io::spi::Data`
            while let Ok(spi_data) = stream.recv().await {
                // send the data
                yield spi_data
            }
        };

        // the final pinned stream that will service
        // the requested subscription
        Ok(tonic::Response::new(
            Box::pin(output) as Self::SlaveSubscribeStream
        ))
    }

    async fn master_receive(
        &self,
        request: tonic::Request<MasterPacket>,
    ) -> Result<tonic::Response<Empty>, tonic::Status> {
        let (_, _, req) = request.into_parts();
        let port = &req.port;
        let contents = &req.data;

        log::trace!(
            "<gRPC> SPI port {} master miso received data: {:?}",
            port,
            contents
        );

        let port = self.grpc_port_to_inner_port(*port)?;

        // we were able to find the port they wanted to subscribe to,
        // so now we're going to send the bytes to the desired UART port
        port.to_master_miso.send(req).unwrap();
        Ok(tonic::Response::new(Empty {}))
    }
}
