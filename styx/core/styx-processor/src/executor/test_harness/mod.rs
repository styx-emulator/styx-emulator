// SPDX-License-Identifier: BSD-2-Clause
//! Executor correctness test harness.
//!
//! Verifies that a [`StrideExecutor`] or [`CustomExecutor`] implementation
//! upholds the round-level accounting contract. A `StrideExecutor` gets most of
//! that contract from the built-in loop. A `CustomExecutor` owns the loop and
//! must satisfy the contract by hand, so the harness matters most there.
//!
//! Build a processor with [`TestProcessorBuilder`], run it with [`run`], then
//! check the result with [`verify_universal_invariants`]:
//!
//! ```ignore
//! let (trace, snapshot) = run(
//!     |b| b.with_executor(ExecutorKind::stride(
//!         DefaultExecutor::with_stride_length(1000))).build(),
//!     5000,
//! )?;
//! verify_universal_invariants(
//!     &trace,
//!     &snapshot,
//!     &Expectations::exact_cycles(5000).with_system_ticks(5),
//! )?;
//! ```
//!
//! [`run`] installs tracing decorators around the primary and per-vCPU event
//! controllers, so the returned [`ExecutorTrace`] records every
//! `post_stride_processing` and every event-distributor tick. Assertions beyond
//! the universal invariants are written directly against that trace.
//!
//! Downstream crates reach this module by enabling the `test-utils` feature on
//! `styx-core` under `[dev-dependencies]`.
//!
//! [`StrideExecutor`]: crate::executor::StrideExecutor
//! [`CustomExecutor`]: crate::executor::CustomExecutor

mod builder;
mod invariants;
mod scripted;
mod trace;
mod trace_decorators;

#[cfg(test)]
mod tests;

pub use builder::{TestProcessor, TestProcessorBuilder};
pub use invariants::{
    verify_universal_invariants, Expectations, InvariantViolation, PostRunSnapshot,
};
pub use scripted::{ScriptedBackend, ScriptedParams};
pub use trace::{ExecutorEvent, ExecutorTrace, ExecutorTraceSpan, TraceEntry, TraceRecorder};

use styx_errors::UnknownError;

use crate::core::VcpuCore;
use crate::executor::ExecutionConstraint;
use crate::processor::PerVcpuSlice;

/// Build a processor, run its executor to completion against `constraint`, and
/// return the recorded trace alongside a snapshot of final time accounting.
///
/// `build` receives a [`TestProcessorBuilder`] with the trace recorder already
/// installed; it adds vCPUs, CPU backends, and the executor under test. Use
/// [`run_with`] when the run itself needs the recorder, e.g. to drop labeled
/// markers into the trace.
pub fn run<F>(
    build: F,
    constraint: impl ExecutionConstraint,
) -> Result<(ExecutorTrace, PostRunSnapshot), UnknownError>
where
    F: FnOnce(TestProcessorBuilder) -> TestProcessor,
{
    run_with(build, |proc, _recorder| {
        proc.executor
            .begin(
                &mut proc.vcpus,
                &mut proc.core,
                &mut proc.plugins,
                &constraint,
            )
            .map(|_| ())
    })
}

/// Like [`run`], but the caller drives the executor itself.
///
/// Use this when a single `begin()` call is not enough: to start and resume the
/// executor several times, or to call [`TraceRecorder::mark`] partway through so
/// later assertions can use [`ExecutorTrace::between`].
pub fn run_with<F, D>(build: F, drive: D) -> Result<(ExecutorTrace, PostRunSnapshot), UnknownError>
where
    F: FnOnce(TestProcessorBuilder) -> TestProcessor,
    D: FnOnce(&mut TestProcessor, &TraceRecorder) -> Result<(), UnknownError>,
{
    let recorder = TraceRecorder::default();
    let mut proc = build(TestProcessorBuilder::new(recorder.clone()));

    drive(&mut proc, &recorder)?;

    // Borrow as a slice so `map` resolves to the by-reference PerVcpuSlice
    // method; the inherent PerVcpu::map consumes the vCPUs.
    let vcpus: &PerVcpuSlice<VcpuCore> = &proc.vcpus;
    let snapshot = PostRunSnapshot {
        core_simulated: proc.core.time.simulated_time(),
        vcpu_simulated: vcpus.map(|_, v| v.time.simulated_time()),
        vcpu_executed: vcpus.map(|_, v| v.time.cycles_executed()),
    };

    Ok((recorder.finish(), snapshot))
}
