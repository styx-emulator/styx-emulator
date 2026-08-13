// SPDX-License-Identifier: BSD-2-Clause
//! The Executor controls how the core executes and when it halts.
//!
//! There are two kinds of executors which are represented as traits to implement
//! into concrete executors. Generally, a user will just choose the the concrete
//! executor that fits their use case. The implementor of an executor must choose
//! the type that fits its functionality best.
//!
//! ## [`StrideExecutor`]
//! Implements the built-in stride-based execution loop. The executor
//! configures stride length and halt conditions and the styx included
//! [`Executor`] handles the emulate -> tick -> check
//! cycle. Prebuilt implementations:
//!
//! - [`DefaultExecutor`] executes the processor as you would expect and is the default in the
//!   processor builder.
//! - [`SingleStepExecutor`] has a stride length of 1 meaning events and peripherals are
//!   ticked after every instruction.
//! - [`ConditionalExecutor`] evaluates a custom function each stride to determine if the processor
//!   should halt.
//!
//! ## [`CustomExecutor`]
//! Takes full control of the execution loop. Appropriate for debuggers,
//! fuzzers, and other tools that need to drive execution themselves.
//!
mod conditional;
mod custom_executor;
mod default;
mod delta;
mod emu_state;
mod execution_constraint;
mod halter;
mod single_step;
mod stride_executor;
#[cfg(test)]
pub(crate) mod test;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_harness;
pub mod time;

pub use conditional::ConditionalExecutor;
pub use custom_executor::CustomExecutor;
pub use default::DefaultExecutor;
pub use execution_constraint::{ExecutionConstraint, ExecutionConstraintConcrete, Forever};
use log::trace;
pub use single_step::SingleStepExecutor;
use std::time::Instant;
pub use stride_executor::StrideExecutor;
use styx_cpu_type::TargetExitReason;
use styx_errors::anyhow::{anyhow, Context};
use styx_errors::UnknownError;

use crate::core::{ProcessorCore, VcpuCore};
use crate::plugins::collection::Plugins;
use crate::processor::{EmulationReport, InstructionReport, PerVcpuSlice};

pub use delta::*;
use emu_state::EmulationRunState;
pub use halter::*;
use time::GlobalDelta;

/// Result of running a single stride on a vCPU.
pub struct StrideResult {
    /// `Some(reason)` if execution should stop, `None` to continue.
    pub exit_reason: Option<TargetExitReason>,
    /// Metrics from this stride (wall time, instruction count).
    pub delta: Delta,
}

/// Selects which executor variant to use.
///
/// Use the explicit constructors ([`ExecutorKind::stride`], [`ExecutorKind::custom`]) to convert a
/// [`StrideExecutor`] or [`CustomExecutor`] into this type, which allows
/// [`ProcessorBuilder::with_executor()`](crate::processor::ProcessorBuilder::with_executor())
/// to accept either kind transparently.
pub enum ExecutorKind {
    /// Uses the built-in stride-based execution loop.
    Stride(Box<dyn StrideExecutor>),
    /// Full control over the execution loop.
    Custom(Box<dyn CustomExecutor>),
}

impl Default for ExecutorKind {
    fn default() -> Self {
        Self::stride(DefaultExecutor::default())
    }
}

impl ExecutorKind {
    /// Wrap a [`StrideExecutor`] into an [`ExecutorKind`].
    pub fn stride(e: impl StrideExecutor + 'static) -> Self {
        ExecutorKind::Stride(Box::new(e))
    }

    /// Wrap a [`CustomExecutor`] into an [`ExecutorKind`].
    pub fn custom(e: impl CustomExecutor + 'static) -> Self {
        ExecutorKind::Custom(Box::new(e))
    }

    /// Initialize the inner executor.
    pub(crate) fn init(
        &mut self,
        proc: &mut crate::processor::BuildingProcessor,
    ) -> Result<(), styx_errors::UnknownError> {
        match self {
            ExecutorKind::Stride(executor) => executor.init(proc),
            ExecutorKind::Custom(executor) => executor.init(proc),
        }
    }
}

/// The main control point for Styx emulation.
///
/// Dispatches to either the built-in stride loop (for [`StrideExecutor`]) or delegates entirely
/// to a [`CustomExecutor`]. In both cases, emulation setup and teardown lifecycle events are
/// called on plugins and event controllers.
///
/// Styx users are not expected to use [`Executor`] directly. Its behavior is explained in the user
/// facing [`StrideExecutor`] and [`CustomExecutor`] traits.
pub struct Executor {
    kind: ExecutorKind,
}

impl Executor {
    pub(crate) fn new(kind: ExecutorKind) -> Self {
        Self { kind }
    }

    /// Start the executor.
    ///
    /// The `conditions` parameter represents the total constraint on emulation, e.g.
    /// how many instructions should we execute in total or how long we should run in
    /// total. This is different from the stride constraint provided by the inner
    /// executor, which defines the size of steps we take to reach the total constraint.
    pub(crate) fn begin(
        &mut self,
        vcpus: &mut PerVcpuSlice<VcpuCore>,
        core: &mut ProcessorCore,
        plugins: &mut Plugins,
        conditions: &impl ExecutionConstraint,
    ) -> Result<Vec<EmulationReport>, UnknownError> {
        match &mut self.kind {
            ExecutorKind::Stride(executor) => {
                let stride_executor = executor.as_mut();

                let stride = stride_executor.get_stride_length();
                stride_executor.emulation_setup(vcpus, core, plugins)?;

                // Runner states holds emulation state for a vCPU.
                // Stride length, execution constraint, total instructions/time executed, and halt function.
                let mut runner_states = vcpus.map(|_, _| RunnerState {
                    state: EmulationRunState::new(stride, conditions),
                    halt: stride_executor
                        .halt_emulation()
                        .unwrap_or_else(default_halter),
                });

                let reports = run_round_robin(
                    vcpus,
                    core,
                    plugins,
                    stride_executor,
                    &mut runner_states,
                    stride,
                )?;

                stride_executor.emulation_teardown(vcpus, core, plugins)?;
                Ok(reports)
            }
            ExecutorKind::Custom(custom_executor) => {
                let constraints = conditions.concrete();
                custom_executor.emulation_setup(vcpus, core, plugins)?;
                // Just pass the constraints and processor innards to the custom executor.
                let reports = custom_executor.execute(vcpus, core, plugins, &constraints)?;
                custom_executor.emulation_teardown(vcpus, core, plugins)?;
                Ok(reports)
            }
        }
    }
}

/// Default emulation setup: calls `processor_start` on plugins, per-vCPU event controllers,
/// and the event distributor.
///
/// Should be called at the beginning of emulation in [`StrideExecutor::emulation_setup()`]
/// and [`CustomExecutor::emulation_setup()`].
pub fn emulation_setup(
    vcpus: &mut PerVcpuSlice<VcpuCore>,
    core: &mut ProcessorCore,
    plugins: &mut Plugins,
) -> Result<(), UnknownError> {
    plugins.on_processor_start(vcpus, core)?;
    for vcpu in vcpus.iter_mut() {
        vcpu.event_controller
            .on_processor_start(vcpu.cpu.as_mut(), &mut vcpu.mmu)?;
    }
    core.event_controller.on_processor_start(vcpus)?;
    Ok(())
}

/// Default emulation teardown: calls `processor_stop` on plugins, per-vCPU event controllers,
/// and the event distributor.
///
/// Should be called at the end of emulation in [`StrideExecutor::emulation_teardown()`]
/// and [`CustomExecutor::emulation_teardown()`].
pub fn emulation_teardown(
    vcpus: &mut PerVcpuSlice<VcpuCore>,
    core: &mut ProcessorCore,
    plugins: &mut Plugins,
) -> Result<(), UnknownError> {
    plugins.on_processor_stop(vcpus, core)?;
    for vcpu in vcpus.iter_mut() {
        vcpu.event_controller
            .on_processor_stop(vcpu.cpu.as_mut(), &mut vcpu.mmu)?;
    }
    core.event_controller.on_processor_stop(vcpus)?;
    Ok(())
}

/// Per-vCPU execution bookkeeping, separate from VCpuCore borrow.
struct RunnerState {
    state: EmulationRunState,
    /// Determines when we should stop execution.
    halt: HaltFn,
}

impl RunnerState {
    /// Execute a stride with a vcpu and updates internal state. Inspect the StrideResult to get optional exit reason.
    fn single_stride(&mut self, vcpu: &mut VcpuCore) -> Result<StrideResult, UnknownError> {
        let (report, emulate_time) = vcpu.execute_and_time(self.state.stride)?;
        vcpu.time
            .record_stride(&report, self.state.stride, emulate_time);
        let instruction_report =
            InstructionReport::from_execution_report(&report, self.state.stride);
        self.state.total_instructions += instruction_report;
        let delta = Delta {
            time: emulate_time,
            count: instruction_report.instructions(),
        };
        self.state.total_wall_time += delta.time;

        if (self.halt)(&report.exit_reason, &delta) {
            trace!("inner indicated halt emulation");
            return Ok(StrideResult {
                exit_reason: Some(report.exit_reason),
                delta,
            });
        }

        post_stride_processing(vcpu, &delta)?;

        let insn_exit = self
            .state
            .instructions_ran(report.instructions_executed.unwrap_or(self.state.stride));
        let exit_reason = self.state.timeout_check().or(insn_exit);

        Ok(StrideResult { exit_reason, delta })
    }
}

/// Run all vCPUs in round-robin until all exit or a fatal error occurs.
///
/// Per-vCPU bookkeeping ([`RunnerState`]) is kept separate from the vCPU slice
/// so that `vcpus` can be passed to the system-level tick without
/// conflicting borrows.
///
/// `stride` is the nominal stride length from [`StrideExecutor::get_stride_length`].
/// The processor clock and always use this nominal value. Individual
/// vCPUs' exit early (before `stride` instructions).
fn run_round_robin(
    vcpus: &mut PerVcpuSlice<VcpuCore>,
    core: &mut ProcessorCore,
    plugins: &mut Plugins,
    executor: &mut dyn StrideExecutor,
    runner_states: &mut PerVcpuSlice<RunnerState>,
    stride: u64,
) -> Result<Vec<EmulationReport>, UnknownError> {
    let mut reports: Vec<Option<TargetExitReason>> = vec![None; vcpus.len()];

    loop {
        let round_start = Instant::now();

        // Phase 1: stride each live vCPU
        for (vcpu_idx, (runner, report)) in
            runner_states.iter_mut().zip(reports.iter_mut()).enumerate()
        {
            if report.is_some() {
                // This means that one cpu is already done and has non-fatal report.
                // I.e. InstructionCountComplete OR ExecutionTimeComplete
                return Err(anyhow!("vcpu exited nonfatal before others"));
            }
            let result = runner.single_stride(&mut vcpus[vcpu_idx])?;
            *report = result.exit_reason;
        }

        let round_wall = round_start.elapsed();

        // Phase 2: advance processor clock, then system-level tick.
        core.time.advance(stride);
        let delta = GlobalDelta::new(stride, round_wall);
        core.event_controller
            .tick(&delta, vcpus)
            .context("error during event distributor tick")?;
        executor
            .tick(&delta, vcpus)
            .context("error during executor tick")?;
        plugins
            .tick(core, &delta, vcpus)
            .context("error during plugin tick")?;

        // Phase 3: termination.
        if reports
            .iter()
            .any(|r| r.as_ref().is_some_and(|t| t.fatal() || t.is_stop_request()))
        {
            // If any have fatal exit or HostStopRequest, then stop
            break;
        }
        if reports.iter().all(Option::is_some) {
            // if all have reports, then stop.
            // Since the above if stops on any fatal or stop requests, this one checks if all have hit their instruction count.
            break;
        }
    }

    let actual_reports = reports.into_iter().enumerate().map(|(i, r)| {
        // All non-exited cores get OtherCoreExited.
        let exit = r.unwrap_or(TargetExitReason::OtherCoreExited);
        EmulationReport {
            exit_reason: exit,
            instructions: runner_states[i].state.total_instructions,
            wall_time: runner_states[i].state.total_wall_time,
        }
    });

    Ok(actual_reports.collect())
}

/// Per-vCPU post-stride processing.
///
/// Processes pending interrupts, ticks the per-vCPU event controller, checks
/// for ISR completion, and runs plugin tickers. System-level peripheral
/// ticking happens separately in [`run_round_robin`].
pub fn post_stride_processing(vcpu: &mut VcpuCore, delta: &Delta) -> Result<(), UnknownError> {
    vcpu.event_controller
        .next(vcpu.cpu.as_mut(), &mut vcpu.mmu)?;
    vcpu.event_controller
        .tick(vcpu.cpu.as_mut(), &mut vcpu.mmu, delta)?;
    Ok(())
}

impl Default for Executor {
    fn default() -> Self {
        Self {
            kind: ExecutorKind::stride(DefaultExecutor::default()),
        }
    }
}
