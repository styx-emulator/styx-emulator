// SPDX-License-Identifier: BSD-2-Clause
//! Implementation of [`SingleEmulationService`]

use std::thread::JoinHandle;
use std::time::Duration;
use styx_core::errors::{StyxMachineError, UnknownError};
use styx_core::grpc::{
    emulation::{
        single_emulation_service_server::SingleEmulationService, StartSingleEmulationRequest,
        StartSingleEmulationResponse,
    },
    utils::{Empty, EmulationState, ProcessorInfo, ResponseStatus},
};
use styx_core::prelude::Forever;
use styx_core::processor::*;
use styx_core::sync::sync::RwLock;
use tonic::{Request, Response};
use tracing::{debug, info, warn};

use crate::svc_executor::{ProcessorState, ServiceExecutorHandle};

/// Keeps track of the [Processor] state
pub struct ProcessorProcess {
    /// Handle to running processor thread.
    _proc_handle: JoinHandle<Result<EmulationReport, UnknownError>>,
    handle: ServiceExecutorHandle,
    /// state of the processor
    emu_state: RwLock<EmulationState>,
    /// port that gRPC service is running on - set when its actally listening
    port: RwLock<Option<u16>>,
    /// full path to the styx trace file
    trace_path: String,
    /// metadata about the processor
    processor_info: ProcessorInfo,
}

impl ProcessorProcess {
    /// make a new `ProcessorProces`
    pub fn new(
        mut processor: Processor,
        handle: ServiceExecutorHandle,
        trace_path: &str,
        target: &styx_core::grpc::args::Target,
    ) -> Result<Self, StyxMachineError> {
        let memr = processor.core.mmu.valid_memory_range();
        let mem_low = memr.start;
        let mem_high = memr.end;
        let arch = processor.core.architecture();
        let arch_name = format!("{}", arch.architecture());
        let arch_variant = arch.architecture_variant();

        let proc_thread = std::thread::spawn(move || processor.run(Forever));

        Ok(Self {
            _proc_handle: proc_thread,
            handle,
            trace_path: trace_path.to_string(),
            emu_state: RwLock::new(EmulationState::Initialized),
            port: RwLock::new(None),

            processor_info: ProcessorInfo {
                target_name: target.as_str_name().into(),
                arch_name,
                arch_variant,
                memory_start: mem_low,
                memory_end: mem_high,
            },
        })
    }

    /// getter for the trace file
    #[inline]
    pub fn trace_path(&self) -> String {
        self.trace_path.clone()
    }

    pub fn port(&self) -> u16 {
        self.port.read().unwrap().unwrap()
    }

    pub fn set_port(&self, port: u16) {
        *self.port.write().unwrap() = Some(port);
    }

    pub fn start_processor(&self) {
        self.handle.set(ProcessorState::Running);
        *self.emu_state.write().unwrap() = EmulationState::Running;
    }

    pub fn processor_info(&self) -> ProcessorInfo {
        self.processor_info.clone()
    }

    pub fn metadata_json(&self, pretty: bool) -> String {
        if pretty {
            serde_json::to_string_pretty(&self.processor_info).unwrap()
        } else {
            serde_json::to_string(&self.processor_info).unwrap()
        }
    }
}

#[async_trait::async_trait]
impl SingleEmulationService for ProcessorProcess {
    /// Start the, already initialized, `Processor`
    async fn start(
        &self,
        request: Request<StartSingleEmulationRequest>,
    ) -> std::result::Result<Response<StartSingleEmulationResponse>, tonic::Status> {
        info!("SingleEmulationService::start");
        let cur_emu_state = *self.emu_state.read().unwrap();
        info!(
            "start: request: {:?}, current_state: {}",
            request.get_ref(),
            cur_emu_state
        );

        match cur_emu_state {
            EmulationState::Initialized | EmulationState::Stopped => {
                debug!(
                    "update state: {} => {} begin handle...",
                    cur_emu_state,
                    EmulationState::Running
                );
                self.start_processor();
                info!("SingleEmulationService::start should be Running");

                Ok(Response::new(StartSingleEmulationResponse {
                    processor_info: Some(self.processor_info.clone()),
                    response_status: Some(ResponseStatus::ok(
                        &format!("port: {}", self.port()),
                        EmulationState::Running,
                    )),
                }))
            }

            _ => {
                // Wrong state
                let msg = format!(
                    "Current state must be {}, but it's {}",
                    EmulationState::Initialized,
                    cur_emu_state
                );
                warn!("{}", msg);
                Ok(Response::new(StartSingleEmulationResponse {
                    processor_info: Some(self.processor_info.clone()),
                    response_status: Some(ResponseStatus::warn(&msg, cur_emu_state)),
                }))
            }
        }
    }

    /// Stop the `Processor`
    async fn stop(
        &self,
        request: Request<Empty>,
    ) -> std::result::Result<Response<ResponseStatus>, tonic::Status> {
        info!("stop: {:?}", request.get_ref());
        let mut cur_emu_state = self.emu_state.write().unwrap();
        match *cur_emu_state {
            EmulationState::Running => {
                self.handle.set(ProcessorState::Stopped);
                *cur_emu_state = EmulationState::Stopped;
                Ok(ResponseStatus::ok_resp("Stopped", EmulationState::Stopped))
            }

            _ => Ok(ResponseStatus::warn(
                &format!(
                    "Current state must be {}, but it's {}",
                    EmulationState::Running,
                    cur_emu_state
                ),
                *cur_emu_state,
            )
            .into()),
        }
    }

    /// Get descriptive information about the `Processor`
    async fn info(
        &self,
        _: Request<Empty>,
    ) -> std::result::Result<Response<ProcessorInfo>, tonic::Status> {
        // delay to return the status before killing this process
        let pi = self.processor_info.clone();
        Ok(Response::new(pi))
    }

    /// Drop the emulator
    async fn drop(
        &self,
        request: Request<Empty>,
    ) -> std::result::Result<Response<ResponseStatus>, tonic::Status> {
        // delay to return the status before killing this process
        const DELAY_MS: u64 = 750;
        let dmesg = format!("(schedule for {DELAY_MS} milliseconds)");
        info!("drop: {:?} {}", request.get_ref(), dmesg);
        let trace_path = self.trace_path();
        kill_task(&trace_path, DELAY_MS);
        *self.emu_state.write().unwrap() = EmulationState::Dropped;
        Ok(ResponseStatus::ok_resp(
            &format!("drop {dmesg}"),
            EmulationState::Dropped,
        ))
    }
}

pub fn kill_task(trace_path: &str, delay_ms: u64) {
    let trace_path = trace_path.to_owned();
    std::thread::spawn(move || {
        debug!("Killing...");

        std::thread::sleep(Duration::from_millis(delay_ms));
        match std::fs::remove_file(&trace_path) {
            Ok(_) => info!("{} removed", trace_path),
            Err(e) => warn!("Failed to remove {}: {}", trace_path, e),
        }
        std::process::exit(std::process::id().try_into().unwrap());
    });
}
