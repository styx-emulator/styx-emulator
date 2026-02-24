// SPDX-License-Identifier: BSD-2-Clause
//! Container for the "core trinity" components and custom builder for the core trinity.
//!
//! The core trinity refers to the cpu, mmu, and event controller in aggregate. They are owned by
//! the [`VcpuCore`]. These are separated from the [`Processor`](super::processor::Processor)
//! because they are used closely during execution. Most calls to the cpu will pass mutable
//! references to the mmu, and event controller. The same is true to most calls to the mmu and event
//! controller taking the other two as mutable references.
//!
use std::sync::Arc;
use std::time::Duration;

use crate::cpu::{CpuBackend, DummyBackend, ExecutionReport};
use crate::event_controller::{
    DummyEventController, EventController, EventDistributor, SingleVcpuEventDistributor,
};
use crate::executor::time::{ProcessorTime, VcpuTime};
use crate::memory::physical::MemoryBackend;
use crate::memory::Mmu;

pub mod builder;
pub use builder::{ProcessorImpl, VcpuBundle};

mod exceptions;
pub use exceptions::*;
use log::trace;
use styx_errors::UnknownError;

/// Placeholder struct for holding processor metadata.
pub struct ProcMeta {}

/// Processor-level shared state.
///
/// Holds shared memory, the processor-wide event distributor, and the
/// processor level time.
///
/// Per-vCPU state lives in [`VcpuCore`].
pub struct ProcessorCore {
    pub memory: Arc<MemoryBackend>,
    pub event_controller: EventDistributor,
    pub time: ProcessorTime,
}

impl ProcessorCore {
    /// Create a dummy [`ProcessorCore`] with default memory and a
    /// [`SingleVcpuEventDistributor`] event distributor.
    pub fn dummy() -> Self {
        Self {
            memory: Arc::new(MemoryBackend::default()),
            event_controller: EventDistributor::new(
                Box::new(SingleVcpuEventDistributor::default()),
            ),
            time: ProcessorTime::default(),
        }
    }
}

pub type VcpuId = u16;

/// Per-vCPU runtime state.
///
/// Each vCPU has its own [`CpuBackend`], [`Mmu`] (own TLB, shared [`MemoryBackend`]),
/// [`EventController`], and [`VcpuTime`].
pub struct VcpuCore {
    pub cpu: Box<dyn CpuBackend>,
    pub mmu: Mmu,
    pub event_controller: EventController,
    pub time: VcpuTime,
}

impl VcpuCore {
    /// Create a dummy [`VcpuCore`] with a no-op CPU, default MMU, and no-op secondary event
    /// controller.
    pub fn dummy() -> Self {
        Self {
            cpu: Box::new(DummyBackend),
            mmu: Mmu::default(),
            event_controller: EventController::new(Box::new(DummyEventController::default()), 0),
            time: VcpuTime::default(),
        }
    }

    pub fn context_save(&mut self) -> Result<(), UnknownError> {
        self.cpu.context_save()?;
        self.mmu.context_save()?;
        Ok(())
    }

    pub fn context_restore(&mut self) -> Result<(), UnknownError> {
        self.cpu.context_restore()?;
        self.mmu.context_save()?;
        Ok(())
    }

    /// Run a stride on a vcpu and track wall time.
    pub fn execute_and_time(
        &mut self,
        stride_constraint: u64,
    ) -> Result<(ExecutionReport, Duration), UnknownError> {
        use std::time::Instant;
        trace!("vcpu started executing");
        let emulate_start = Instant::now();
        let report =
            self.cpu
                .execute(&mut self.mmu, &mut self.event_controller, stride_constraint)?;
        let emulate_time = Instant::now() - emulate_start;

        Ok((report, emulate_time))
    }
}
