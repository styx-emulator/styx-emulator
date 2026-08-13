// SPDX-License-Identifier: BSD-2-Clause
//! Test processor builder with tracing wrappers pre-installed.

use std::sync::Arc;

use crate::core::{ProcessorCore, VcpuCore, VcpuId};
use crate::cpu::CpuBackend;
use crate::event_controller::{
    DummyEventController, EventController, EventControllerImpl, EventDistributor,
    EventDistributorImpl, SingleVcpuEventDistributor,
};
use crate::executor::test_harness::trace::TraceRecorder;
use crate::executor::test_harness::trace_decorators::{
    TracingEventController, TracingEventDistributor,
};
use crate::executor::time::{ProcessorTime, VcpuTime};
use crate::executor::{Executor, ExecutorKind};
use crate::memory::physical::MemoryBackend;
use crate::memory::Mmu;
use crate::plugins::collection::Plugins;
use crate::processor::PerVcpu;

/// A minimal processor wired up for executor testing, with tracing decorators
/// already installed around the primary and per-vCPU event controllers.
pub struct TestProcessor {
    pub vcpus: PerVcpu<VcpuCore>,
    pub core: ProcessorCore,
    pub plugins: Plugins,
    pub executor: Executor,
}

/// Builder for a [`TestProcessor`].
///
/// Defaults:
/// - 1 vCPU running [`DummyBackend`]
/// - [`SingleVcpuEventDistributor`] as the primary EC impl
/// - No plugins
/// - Executor **must** be set via [`TestProcessorBuilder::with_executor`].
pub struct TestProcessorBuilder {
    recorder: TraceRecorder,
    vcpu_backends: Vec<Box<dyn CpuBackend>>,
    vcpu_ec_impls: Vec<Box<dyn EventControllerImpl>>,
    primary_impl: Box<dyn EventDistributorImpl>,
    executor: Option<ExecutorKind>,
}

impl TestProcessorBuilder {
    pub fn new(recorder: TraceRecorder) -> Self {
        Self {
            recorder,
            vcpu_backends: Vec::new(),
            vcpu_ec_impls: Vec::new(),
            primary_impl: Box::new(SingleVcpuEventDistributor::default()),
            executor: None,
        }
    }

    /// Append a vCPU with the given CPU backend.
    ///
    /// Uses the default per-vCPU event controller impl [`DummyEventController`].
    pub fn with_vcpu_backend(mut self, backend: Box<dyn CpuBackend>) -> Self {
        self.vcpu_backends.push(backend);
        self.vcpu_ec_impls
            .push(Box::new(DummyEventController::default()));
        self
    }

    /// Set the executor under test. Required.
    pub fn with_executor(mut self, exec: ExecutorKind) -> Self {
        self.executor = Some(exec);
        self
    }

    /// Build the [`TestProcessor`].
    ///
    /// Panics if no vCPUs where added.
    pub fn build(self) -> TestProcessor {
        assert_eq!(self.vcpu_backends.len(), self.vcpu_ec_impls.len());

        // Wrap event distributor impl with tracing.
        let tracing_distributor: Box<dyn EventDistributorImpl> = Box::new(
            TracingEventDistributor::new(self.primary_impl, self.recorder.clone()),
        );
        let primary = EventDistributor::new(tracing_distributor);

        // Wrap each per-vCPU event controller impl with tracing.
        let vcpus: Vec<VcpuCore> = self
            .vcpu_backends
            .into_iter()
            .zip(self.vcpu_ec_impls)
            .enumerate()
            .map(|(idx, (cpu, ec_impl))| {
                let vcpu: VcpuId = idx.try_into().expect("too many vcpus");
                let tracing_ec: Box<dyn EventControllerImpl> = Box::new(
                    TracingEventController::new(ec_impl, vcpu, self.recorder.clone()),
                );
                VcpuCore {
                    cpu,
                    mmu: Mmu::default(),
                    event_controller: EventController::new(tracing_ec, vcpu),
                    time: VcpuTime::default(),
                }
            })
            .collect();
        let vcpus = PerVcpu::collect(vcpus).expect("must have at least one vcpu");

        let core = ProcessorCore {
            memory: Arc::new(MemoryBackend::default()),
            event_controller: primary,
            time: ProcessorTime::default(),
        };

        let plugins = Plugins { plugins: vec![] };

        let executor_kind = self
            .executor
            .expect("TestProcessorBuilder::build requires with_executor");
        let executor = Executor::new(executor_kind);

        TestProcessor {
            vcpus,
            core,
            plugins,
            executor,
        }
    }
}
