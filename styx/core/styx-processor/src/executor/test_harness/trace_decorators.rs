// SPDX-License-Identifier: BSD-2-Clause
//! Tracing decorators for the event distributor and per-vCPU event controllers.

use std::sync::Arc;

use styx_errors::UnknownError;

use crate::core::{VcpuCore, VcpuId};
use crate::cpu::CpuBackend;
use crate::event_controller::{
    ActivateIRQnError, EventControllerImpl, EventDistributorImpl, Exception, ExceptionNumber,
    InterruptExecuted, OptionalFeatureError,
};
use crate::executor::test_harness::trace::{ExecutorEvent, TraceRecorder};
use crate::executor::time::GlobalDelta;
use crate::executor::Delta;
use crate::memory::{MemoryBackend, Mmu};
use crate::processor::{Config, PerVcpuSlice};

/// Wraps a [`EventDistributorImpl`] so that every `tick()` call is
/// recorded into a [`TraceRecorder`]. All other methods forward unchanged.
pub struct TracingEventDistributor {
    inner: Box<dyn EventDistributorImpl>,
    recorder: TraceRecorder,
}

impl TracingEventDistributor {
    pub fn new(inner: Box<dyn EventDistributorImpl>, recorder: TraceRecorder) -> Self {
        Self { inner, recorder }
    }
}

impl EventDistributorImpl for TracingEventDistributor {
    fn on_processor_start(
        &mut self,
        vcpus: &mut PerVcpuSlice<VcpuCore>,
    ) -> Result<(), UnknownError> {
        self.inner.on_processor_start(vcpus)
    }

    fn on_processor_stop(
        &mut self,
        vcpus: &mut PerVcpuSlice<VcpuCore>,
    ) -> Result<(), UnknownError> {
        self.inner.on_processor_stop(vcpus)
    }

    fn tick(
        &mut self,
        delta: &GlobalDelta,
        pending_irqs: &[ExceptionNumber],
        vcpus: &mut PerVcpuSlice<VcpuCore>,
    ) -> Result<(), UnknownError> {
        // Forward first, then record. Only log a tick that completed.
        let result = self.inner.tick(delta, pending_irqs, vcpus);
        if result.is_ok() {
            self.recorder.record(ExecutorEvent::SystemTick {
                delta: delta.clone(),
            });
        }
        result
    }

    fn init(
        &mut self,
        vcpus: &mut PerVcpuSlice<VcpuCore>,
        memory: &Arc<MemoryBackend>,
        config: &mut Config,
    ) -> Result<(), UnknownError> {
        self.inner.init(vcpus, memory, config)
    }

    fn reset(&mut self, mmu: &mut crate::memory::Mmu) -> Result<(), UnknownError> {
        self.inner.reset(mmu)
    }
}

/// Wraps an [`EventControllerImpl`] so that every `tick()` call is recorded
/// into a [`TraceRecorder`] tagged with the owning vCPU index. All other
/// methods forward unchanged.
pub struct TracingEventController {
    inner: Box<dyn EventControllerImpl>,
    vcpu_index: VcpuId,
    recorder: TraceRecorder,
}

impl TracingEventController {
    pub fn new(
        inner: Box<dyn EventControllerImpl>,
        vcpu_index: VcpuId,
        recorder: TraceRecorder,
    ) -> Self {
        Self {
            inner,
            vcpu_index,
            recorder,
        }
    }
}

impl EventControllerImpl for TracingEventController {
    fn next(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Result<InterruptExecuted, UnknownError> {
        self.inner.next(cpu, mmu)
    }

    fn latch(&mut self, event: ExceptionNumber) -> Result<(), ActivateIRQnError> {
        self.inner.latch(event)
    }

    fn execute(
        &mut self,
        irq: ExceptionNumber,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Result<InterruptExecuted, ActivateIRQnError> {
        self.inner.execute(irq, cpu, mmu)
    }

    fn on_processor_start(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Result<(), UnknownError> {
        self.inner.on_processor_start(cpu, mmu)
    }

    fn on_processor_stop(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Result<(), UnknownError> {
        self.inner.on_processor_stop(cpu, mmu)
    }

    fn tick(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        delta: &Delta,
    ) -> Result<(), UnknownError> {
        let result = self.inner.tick(cpu, mmu, delta);
        if result.is_ok() {
            self.recorder.record(ExecutorEvent::VcpuTick {
                vcpu: self.vcpu_index,
                delta: delta.clone(),
            });
        }
        result
    }

    fn finish_interrupt(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Option<ExceptionNumber> {
        self.inner.finish_interrupt(cpu, mmu)
    }

    fn init(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut MemoryBackend,
        config: &mut Config,
    ) -> Result<(), UnknownError> {
        self.inner.init(cpu, mmu, config)
    }

    fn reset(&mut self, cpu: &mut dyn CpuBackend, mmu: &mut Mmu) -> Result<(), UnknownError> {
        self.inner.reset(cpu, mmu)
    }

    fn current_exception(&mut self) -> Result<Option<Exception>, OptionalFeatureError> {
        self.inner.current_exception()
    }
}

#[cfg(test)]
mod tests {
    use super::{TracingEventController, TracingEventDistributor};
    use crate::core::VcpuCore;
    use crate::cpu::DummyBackend;
    use crate::event_controller::{
        EventController, EventControllerImpl, EventDistributorImpl, SingleVcpuEventDistributor,
    };
    use crate::executor::test_harness::trace::{ExecutorEvent, TraceRecorder};
    use crate::executor::time::{GlobalDelta, VcpuTime};
    use crate::executor::Delta;
    use crate::memory::Mmu;
    use crate::processor::PerVcpuSlice;
    use std::time::Duration;

    #[test]
    fn tick_is_forwarded_and_recorded() {
        let rec = TraceRecorder::default();
        let inner: Box<dyn EventDistributorImpl> = Box::new(SingleVcpuEventDistributor::default());
        let mut wrapped = TracingEventDistributor::new(inner, rec.clone());

        let mut vcpus = vec![VcpuCore {
            cpu: Box::new(DummyBackend),
            mmu: Mmu::default(),
            event_controller: EventController::default(),
            time: VcpuTime::default(),
        }];

        let delta = GlobalDelta::new(1234, Duration::from_millis(2));
        let vcpus = PerVcpuSlice::new_mut(&mut vcpus).expect("one vcpu");
        wrapped.tick(&delta, &[], vcpus).unwrap();

        // Drop the wrapped decorator to release its clone of the recorder.
        drop(wrapped);

        let trace = rec.finish();
        let ticks: Vec<_> = trace
            .entries()
            .iter()
            .filter_map(|e| match &e.event {
                ExecutorEvent::SystemTick { delta } => Some(delta.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(ticks.len(), 1);
        assert_eq!(ticks[0].simulated_time, 1234);
    }

    #[test]
    fn per_vcpu_tick_is_forwarded_and_recorded() {
        use crate::cpu::CpuBackend;

        let rec = TraceRecorder::default();

        let inner: Box<dyn EventControllerImpl> =
            Box::new(crate::event_controller::DummyEventController::default());
        let mut wrapped = TracingEventController::new(inner, 3, rec.clone());

        let mut cpu: Box<dyn CpuBackend> = Box::new(DummyBackend);
        let mut mmu = Mmu::default();
        let delta = Delta {
            time: Duration::from_millis(1),
            count: 777,
        };

        wrapped.tick(cpu.as_mut(), &mut mmu, &delta).unwrap();

        // Drop the wrapped decorator to release its clone of the recorder.
        drop(wrapped);

        let trace = rec.finish();
        let events: Vec<_> = trace
            .entries()
            .iter()
            .filter_map(|e| match &e.event {
                ExecutorEvent::VcpuTick { vcpu, delta } => Some((*vcpu, delta.count)),
                _ => None,
            })
            .collect();
        assert_eq!(events, vec![(3, 777)]);
    }
}
