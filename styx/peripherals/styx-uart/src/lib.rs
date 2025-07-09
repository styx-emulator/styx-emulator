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
//! # styx-uart
//!
//! This crate defines a generic UART interface and controller that processors can use to
//! add UART functionality.  The [`UartImpl`] trait holds implementation specific
//! methods, and will need to be implemented for each processor.
//!
//! Usage:
//!
//! A processor should add a [`UartController`] as a peripheral, with as many [`UartInterface`]
//! as needed.  [`UartInterface::inner`] holds processor specific functionality like what memory
//! hooks to register, or what the reset state looks like.  This needs to be implemented for each
//! processor but will likely look similar between implementations.
//!
//! Example:
//! ```rust
//! use styx_core::prelude::*;
//! use styx_core::runtime::ProcessorRuntime;
//! use styx_core::cpu::PcodeBackend;
//! use styx_core::memory::Mmu;
//! use styx_core::event_controller::Peripheral;
//! use styx_core::arch::ArchEndian;
//! use styx_core::arch::arm::ArmVariants;
//! use styx_core::arch::Arch;
//! use styx_uart::{UartController, UartInterface, UartImpl, IntoUartImpl};
//!
//! use tokio::sync::broadcast;
//!
//! pub struct ExampleProcessor {}
//!
//! pub struct UartInner {}
//!
//! impl UartImpl for UartInner {}
//!
//! impl IntoUartImpl for UartInner {
//!     fn new(
//!         self,
//!         mosi_tx: broadcast::Receiver<u8>,
//!         miso_rx: broadcast::Sender<u8>,
//!         interface_id: String,
//!     ) -> Result<Box<dyn UartImpl>, UnknownError> {
//!         Ok(Box::new(self))
//!     }
//! }
//!
//! fn uarts() -> Vec<UartInterface> {
//!     vec![
//!         UartInterface::new(
//!             "0".into(),
//!             UartInner {},
//!         ),
//!     ]
//! }
//!
//! fn build_processor(
//!     _runtime: &ProcessorRuntime,
//!     cpu_backend: Backend,
//! ) {
//!     let cpu = Box::new(PcodeBackend::new_engine(
//!         Arch::Arm,
//!         ArmVariants::ArmCortexM4,
//!         ArchEndian::LittleEndian,
//!     ));
//!     let mut mmu = Mmu::default();
//!
//!     let peripherals: Vec<Box<dyn Peripheral>> = vec![Box::new(UartController::new(uarts()))];
//!
//!     // continue building rest of processor
//! }
//! ```
use styx_core::errors::UnknownError;
use styx_core::grpc::io::uart::uart_port_server::{UartPort, UartPortServer};
use styx_core::grpc::io::uart::{self, RxData, TxData};
use styx_core::prelude::*;
use styx_core::sync::sync::Arc;

use as_any::{AsAny, Downcast};
use async_trait::async_trait;
use derivative::Derivative;
use std::any::TypeId;
use std::pin::Pin;
use thiserror::Error;
use tokio::sync::broadcast;
use tokio_stream::{Stream, StreamExt};
use tracing::{debug, error, trace};

#[derive(Debug, Error)]
pub enum GenericUARTError {
    #[error("Interface {0} does not exist")]
    InvalidInterface(String),
}

impl From<GenericUARTError> for tonic::Status {
    fn from(value: GenericUARTError) -> Self {
        tonic::Status::invalid_argument(value.to_string())
    }
}

/// Uninitialized [`UartImpl`] that will be give channels for tx and rx.
///
/// Master is the grpc server/external uart source and slave is the target uart interface.
///
/// mosi: Master out/Slave in
/// miso: Master in/Slave out
///
/// Currently they have a limited buffer size so the rx should be queried
/// frequently (i.e. every tick). In the future we could have a buffer on the
/// UartInterface with an async task to automatically buffer bytes for target
/// consumption.
pub trait IntoUartImpl {
    /// Registers the memory mapped hooks needed for use by this
    /// peripheral.
    #[allow(clippy::wrong_self_convention)]
    #[allow(clippy::new_ret_no_self)]
    fn new(
        self,
        mosi_tx: broadcast::Receiver<u8>,
        miso_rx: broadcast::Sender<u8>,
        interface_id: String,
    ) -> Result<Box<dyn UartImpl>, UnknownError>;
}

/// Processor specific Uart interface implementations need to implement this trait.
/// Default empty implementations are provided for all functions, in the event that
/// not all are needed.
pub trait UartImpl: AsAny + Send {
    /// Registers the memory mapped hooks needed for use by this
    /// peripheral.
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
}

#[derive(Debug)]
pub struct UartMasterInterface {
    pub interface_id: String,
    pub miso: broadcast::Sender<u8>,
    pub mosi: broadcast::Sender<u8>,
}

/// A generic Uart interface
#[derive(Derivative)]
#[derivative(Debug)]
pub struct UartInterface {
    pub interface_id: String,
    #[derivative(Debug = "ignore")]
    pub inner: Box<dyn UartImpl>,
    miso: broadcast::Sender<u8>,
    mosi: broadcast::Sender<u8>,
}

impl UartInterface {
    pub fn new(interface_id: String, inner: impl IntoUartImpl) -> Self {
        let (miso_tx, _miso_rx) = broadcast::channel(2048);
        let (mosi_tx, _mosi_rx) = broadcast::channel(2048);

        let inner = inner
            .new(mosi_tx.subscribe(), miso_tx.clone(), interface_id.clone())
            .unwrap();

        Self {
            interface_id: interface_id.clone(),
            inner,
            miso: miso_tx.clone(),
            mosi: mosi_tx,
        }
    }

    pub fn master(&self) -> UartMasterInterface {
        UartMasterInterface {
            interface_id: self.interface_id.clone(),
            miso: self.miso.clone(),
            mosi: self.mosi.clone(),
        }
    }
}

#[derive(Debug)]
/// The main [Peripheral] holding all Uart ports.
///
/// The Uart controller holds any number of Uart interfaces, as most processors have more than one.
pub struct UartController {
    uart_interfaces: Vec<UartInterface>,
}

impl UartController {
    pub fn get<T: UartImpl + 'static>(&mut self, id: &str) -> Option<&mut T> {
        self.uart_interfaces.iter_mut().find_map(|i| {
            if i.interface_id == id {
                i.inner.as_mut().downcast_mut::<T>()
            } else {
                None
            }
        })
    }

    /// [`Self::get()`] but we convenient error context.
    pub fn try_get<T: UartImpl + 'static>(&mut self, id: &str) -> Result<&mut T, UnknownError> {
        self.get(id).with_context(|| {
            format!(
                "could not get uart interface with id '{id}' and type '{:?}'",
                TypeId::of::<T>()
            )
        })
    }

    pub fn new(uart_interfaces: Vec<UartInterface>) -> Self {
        UartController { uart_interfaces }
    }

    // TODO: why do we not use this...
    // TODO: it might not be a safe assumption that 1IRQ == 1 UART port
    pub fn irq_to_uart_port(
        &self,
        irq: ExceptionNumber,
    ) -> Result<&UartInterface, GenericUARTError> {
        // search for the uart port that owns the IRQn
        for uart in self.uart_interfaces.iter() {
            if uart.inner.irqs().contains(&irq) {
                return Ok(uart);
            }
        }

        // no uart port matched
        Err(GenericUARTError::InvalidInterface(format!(
            "No interface owns IRQ {}",
            irq
        )))
    }

    pub fn master(&self) -> Vec<UartMasterInterface> {
        self.uart_interfaces.iter().map(|i| i.master()).collect()
    }
}

/// Thin wrapper struct over all UART messages
///
/// This is used to broadcast data in the many to many channels
/// and provide easy means for RO or Copy mut access to the message
#[derive(Debug, Clone)]
pub struct UartData {
    pub data: Arc<Box<[u8]>>,
    pub port: String,
    pub is_rx: bool,
}

impl From<UartData> for uart::BytesMessage {
    fn from(value: UartData) -> Self {
        if value.is_rx {
            uart::BytesMessage {
                port: value.port,
                data: Some(uart::bytes_message::Data::RxData(RxData {
                    data: value.data.clone().to_vec(),
                })),
            }
        } else {
            uart::BytesMessage {
                port: value.port,
                data: Some(uart::bytes_message::Data::TxData(TxData {
                    data: value.data.clone().to_vec(),
                })),
            }
        }
    }
}

impl Peripheral for UartController {
    // todo reset state?

    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        // uart interface init
        for uart in self.uart_interfaces.iter_mut() {
            uart.inner.init(proc)?;
        }

        // uart service
        // create inner wrapper struct that implements the service
        let service = UartPortServer::new(UartControllerService {
            uart_interfaces: self.master(),
        });

        proc.routes.add_service(service);

        Ok(())
    }

    fn name(&self) -> &str {
        "uart controller"
    }

    /// routes to the correct underlying uart port
    fn post_event_hook(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _event_controller: &mut dyn EventControllerImpl,
        _num: ExceptionNumber,
    ) -> Result<(), UnknownError> {
        // let port = self.irq_to_uart_port(num)?;
        // port.inner.post_event_hook(num)
        Ok(())
    }

    /// gets all the inner IRQs that this [`UartController`] should route
    fn irqs(&self) -> Vec<ExceptionNumber> {
        self.uart_interfaces
            .iter()
            .flat_map(|x| x.inner.irqs())
            .collect()
    }

    fn tick(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        event_controller: &mut dyn EventControllerImpl,
        _delta: &styx_core::executor::Delta,
    ) -> Result<(), UnknownError> {
        for interface in self.uart_interfaces.iter_mut() {
            interface.inner.tick(cpu, mmu, event_controller)?;
        }
        Ok(())
    }

    fn reset(&mut self, _cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        Ok(())
    }
}

#[derive(Debug)]
enum SubscribeDirection {
    Rx = 0,
    Tx = 1,
    Both = 2,
}
impl From<Option<styx_core::grpc::io::uart::subscribe_request::Direction>> for SubscribeDirection {
    fn from(value: Option<styx_core::grpc::io::uart::subscribe_request::Direction>) -> Self {
        match value.unwrap() {
            styx_core::grpc::io::uart::subscribe_request::Direction::Rx(_) => Self::Rx,
            styx_core::grpc::io::uart::subscribe_request::Direction::Tx(_) => Self::Tx,
            styx_core::grpc::io::uart::subscribe_request::Direction::Both(_) => Self::Both,
        }
    }
}

#[derive(Debug)]
struct UartControllerService {
    uart_interfaces: Vec<UartMasterInterface>,
}

impl UartControllerService {
    fn grpc_port_to_inner_port(
        &self,
        grpc_port: &str,
    ) -> Result<&UartMasterInterface, GenericUARTError> {
        for u in self.uart_interfaces.iter() {
            if u.interface_id == grpc_port {
                return Ok(u);
            }
        }
        Err(GenericUARTError::InvalidInterface(grpc_port.to_string()))
    }
}

#[async_trait]
/// Implementations of the GRPC endpoints for UART procedures.
impl UartPort for UartControllerService {
    type SubscribeStream =
        Pin<Box<dyn Stream<Item = Result<uart::BytesMessage, tonic::Status>> + Send + 'static>>;

    async fn receive(
        &self,
        request: tonic::Request<uart::BytesMessage>,
    ) -> tonic::Result<tonic::Response<uart::Ack>> {
        let (_, _, bytes_message) = request.into_parts();
        let port_string = bytes_message.port;

        debug!(
            "<gRPC> UART interface {} received data: {:?}",
            &port_string, &bytes_message.data,
        );

        let uart_ifc = self.grpc_port_to_inner_port(&port_string)?;

        if let Some(uart::bytes_message::Data::RxData(rx_data)) = bytes_message.data {
            for byte in rx_data.data {
                uart_ifc.mosi.send(byte).unwrap();
            }
        }
        Ok(tonic::Response::new(uart::Ack {}))
    }

    async fn subscribe(
        &self,
        request: tonic::Request<uart::SubscribeRequest>,
    ) -> Result<tonic::Response<Self::SubscribeStream>, tonic::Status> {
        let (_, _, subscribe_request) = request.into_parts();
        let port_string = subscribe_request.port.unwrap().port;
        let direction: SubscribeDirection = subscribe_request.direction.into();

        trace!(
            "<gRPC> UART port {} {:?} is being subscribed to",
            &port_string,
            direction
        );

        let uart_port = self.grpc_port_to_inner_port(&port_string)?;

        match direction {
            SubscribeDirection::Tx => {
                // tx is miso?
                // let mut stream = uart_port.subscribe_tx();
                let mut stream = uart_port.miso.subscribe();

                let output = async_stream::try_stream! {
                    // get the next `UartData` and convert it into a
                    // `uart::BytesMessage`
                    while let Ok(uart_data) = stream.recv().await {
                        let uart_data = UartData {
                            data: Arc::new(vec![uart_data].into_boxed_slice()),
                            port: port_string.clone(),
                            is_rx: false,
                        };
                        // send the `BytesMessage`
                        yield uart_data.into()
                    }
                };
                // the final pinned stream that will service
                // the requested subscription
                Ok(tonic::Response::new(
                    Box::pin(output) as Self::SubscribeStream
                ))
            }
            SubscribeDirection::Rx => {
                // rx is mosi?
                // let mut stream = uart_port.subscribe_rx();
                let mut stream = uart_port.mosi.subscribe();
                let output = async_stream::try_stream! {
                    // get the next `UartData` and convert it into a
                    // `uart::BytesMessage`
                    while let Ok(uart_data) = stream.recv().await {
                        let uart_data = UartData {
                            data: Arc::new(vec![uart_data].into_boxed_slice()),
                            port: port_string.clone(),
                            is_rx: true,
                        };
                        // send the `BytesMessage`
                        yield uart_data.into()
                    }
                };
                // the final pinned stream that will service
                // the requested subscription
                Ok(tonic::Response::new(
                    Box::pin(output) as Self::SubscribeStream
                ))
            }
            SubscribeDirection::Both => {
                let mut stream_tx = uart_port.miso.subscribe();

                let port_string2 = port_string.clone();
                let output_tx = async_stream::try_stream! {
                    // get the next `UartData` and convert it into a
                    // `uart::BytesMessage`
                    while let Ok(uart_data) = stream_tx.recv().await {
                        let uart_data = UartData {
                            data: Arc::new(vec![uart_data].into_boxed_slice()),
                            port: port_string2.clone(),
                            is_rx: false,
                        };
                        // send the `BytesMessage`
                        yield uart_data.into()
                    }
                };

                let mut stream_rx = uart_port.mosi.subscribe();

                let output_rx = async_stream::try_stream! {
                    // get the next `UartData` and convert it into a
                    // `uart::BytesMessage`
                    while let Ok(uart_data) = stream_rx.recv().await {
                        let uart_data = UartData {
                            data: Arc::new(vec![uart_data].into_boxed_slice()),
                            port: port_string.clone(),
                            is_rx: true,
                        };
                        // send the `BytesMessage`
                        yield uart_data.into()
                    }
                };

                let merged_output = output_rx.merge(output_tx);

                Ok(tonic::Response::new(
                    Box::pin(merged_output) as Self::SubscribeStream
                ))
                // create streams for both rx and tx
                // merge streams with StreamExt
                // return pinned, merged stream
            }
        }
    }
}
