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
//! Blanket implementation of the Processor service as defined
//! in [`styx_grpc`].
//!
//! Currently only implements stop and memory read + write.
//!
//! NOTE: stopped working on this due to scope creep of another
//!       ticket, and didn't want to drop all the work in-place
//! TODO: tests
//! TODO: test harness
//! TODO: finish implementation
//! TODO: make client library in rust/python
use crate::ProcessorImpl;
use async_trait::async_trait;
use std::pin::Pin;
use styx_cpu::CpuBackend;
use styx_grpc::machines::processor::processor_service_server::{
    ProcessorService, ProcessorServiceServer,
};
use styx_grpc::machines::processor::{
    AddCodeHookRequest, AddReadMemoryHookRequest, AddWriteMemoryHookRequest, CodeHookEvent,
    MemoryRegion, ReadMemoryHookEvent, ReadMemoryRequest, ReadMemoryResponse,
    RemoveCodeHookRequest, RemoveCodeHookResponse, RemoveReadMemoryHookRequest,
    RemoveReadMemoryHookResponse, RemoveWriteMemoryHookRequest, RemoveWriteMemoryHookResponse,
    StartExecutionRequest, StartExecutionResponse, StopExecutionRequest, StopExecutionResponse,
    WriteMemoryHookEvent, WriteMemoryRequest, WriteMemoryResponse,
};
use styx_sync::sync::Weak;
use tokio_stream::Stream;

/// Service to control a [`ProcessorImpl`]
///
/// Right now it doesn't use token's or any sort of validation on if you
/// are supposed to be able to talk to it, or return a uuid etc. so you
/// know which one you are talking to
#[derive(Debug)]
pub struct ProcessorServiceImpl {
    inner: CpuBackend,
}

impl ProcessorServiceImpl {
    /// Constructs a new [`ProcessorServiceImpl`] from a [`Weak<dyn Processor>`]
    /// that will be connected to this `IPC` service
    pub fn from_weak_processor(proc: Weak<dyn ProcessorImpl>) -> Self {
        Self {
            inner: proc.upgrade().unwrap().cpu(),
        }
    }

    /// Consumes `self` to return a fully-realized server implementation
    pub fn server(self) -> ProcessorServiceServer<Self> {
        ProcessorServiceServer::new(self)
    }
}

#[async_trait]
impl ProcessorService for ProcessorServiceImpl {
    async fn read_memory(
        &self,
        request: tonic::Request<ReadMemoryRequest>,
    ) -> tonic::Result<tonic::Response<ReadMemoryResponse>> {
        let req = request.into_inner();
        if let Some(region) = req.region {
            // attempt the memory read from the client
            if let Ok(data) = self
                .inner
                .read_memory_vec(region.address, region.size as usize)
            {
                // we got the data from the backend
                let out_region = MemoryRegion {
                    address: region.address,
                    size: region.size,
                    data,
                };

                // send the ok response
                return tonic::Result::Ok(tonic::Response::new(ReadMemoryResponse {
                    token: None,
                    region: Some(out_region),
                }));
            }

            // if there was an error, then we return error below
        }

        tonic::Result::Err(tonic::Status::internal("Bad Region"))
    }

    async fn write_memory(
        &self,
        request: tonic::Request<WriteMemoryRequest>,
    ) -> tonic::Result<tonic::Response<WriteMemoryResponse>> {
        let req = request.into_inner();

        if let Some(region) = req.region {
            // attempt to write memory to the desired location
            if self
                .inner
                .write_memory(region.address, &region.data)
                .is_ok()
            {
                // we got the data from the backend
                let out_region = MemoryRegion {
                    address: region.address,
                    size: region.size,
                    data: Vec::new(),
                };

                // send the ok response
                return tonic::Result::Ok(tonic::Response::new(WriteMemoryResponse {
                    token: None,
                    region: Some(out_region),
                }));
            }

            // if there was an error, then we return error below
        }

        tonic::Result::Err(tonic::Status::internal("Bad Region + data"))
    }

    async fn start_execution(
        &self,
        _request: tonic::Request<StartExecutionRequest>,
    ) -> tonic::Result<tonic::Response<StartExecutionResponse>> {
        todo!()
    }

    async fn stop_execution(
        &self,
        _request: tonic::Request<StopExecutionRequest>,
    ) -> tonic::Result<tonic::Response<StopExecutionResponse>> {
        match self.inner.stop() {
            Ok(_) => tonic::Result::Ok(tonic::Response::new(StopExecutionResponse::default())),
            Err(_) => tonic::Result::Err(tonic::Status::internal("Failed to stop")),
        }
    }

    /// Server streaming response type for the AddCodeHook method.
    type AddCodeHookStream =
        Pin<Box<dyn Stream<Item = tonic::Result<CodeHookEvent>> + Send + 'static>>;

    async fn add_code_hook(
        &self,
        _request: tonic::Request<AddCodeHookRequest>,
    ) -> tonic::Result<tonic::Response<Self::AddCodeHookStream>> {
        todo!()
    }

    async fn remove_code_hook(
        &self,
        _request: tonic::Request<RemoveCodeHookRequest>,
    ) -> tonic::Result<tonic::Response<RemoveCodeHookResponse>> {
        todo!()
    }

    /// Server streaming response type for the AddWriteMemoryHook method.
    type AddWriteMemoryHookStream =
        Pin<Box<dyn Stream<Item = tonic::Result<WriteMemoryHookEvent>> + Send + 'static>>;

    async fn add_write_memory_hook(
        &self,
        _request: tonic::Request<AddWriteMemoryHookRequest>,
    ) -> tonic::Result<tonic::Response<Self::AddWriteMemoryHookStream>> {
        todo!()
    }

    async fn remove_write_memory_hook(
        &self,
        _request: tonic::Request<RemoveWriteMemoryHookRequest>,
    ) -> tonic::Result<tonic::Response<RemoveWriteMemoryHookResponse>> {
        todo!()
    }

    /// Server streaming response type for the AddReadMemoryHook method.
    type AddReadMemoryHookStream =
        Pin<Box<dyn Stream<Item = tonic::Result<ReadMemoryHookEvent>> + Send + 'static>>;

    async fn add_read_memory_hook(
        &self,
        _request: tonic::Request<AddReadMemoryHookRequest>,
    ) -> tonic::Result<tonic::Response<Self::AddReadMemoryHookStream>> {
        todo!()
    }

    async fn remove_read_memory_hook(
        &self,
        _request: tonic::Request<RemoveReadMemoryHookRequest>,
    ) -> tonic::Result<tonic::Response<RemoveReadMemoryHookResponse>> {
        todo!()
    }
}
