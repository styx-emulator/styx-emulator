// SPDX-License-Identifier: BSD-2-Clause

use static_assertions::assert_obj_safe;
use styx_errors::UnknownError;

use crate::core::{ProcessorCore, VcpuCore};
use crate::executor::ExecutionConstraintConcrete;
use crate::plugins::collection::Plugins;
use crate::processor::{BuildingProcessor, EmulationReport, PerVcpuSlice};

use super::{emulation_setup, emulation_teardown};

assert_obj_safe!(CustomExecutor);

/// Executor that fully owns the execution loop.
///
/// Unlike [`StrideExecutor`](super::StrideExecutor) which participates in the built-in
/// stride-based loop, a `CustomExecutor` is given full control over how and when instructions
/// are executed. This is appropriate for tools that need to drive execution themselves, such as
/// debuggers and fuzzers.
///
/// The [`Executor`](super::Executor) still handles calling `processor_start` / `processor_stop`
/// lifecycle events on plugins and event controllers before and after
/// [`CustomExecutor::execute()`]. The custom executor is responsible for:
///
/// - Calling [`post_stride_processing`](super::post_stride_processing) (or equivalent) after
///   each vCPU stride to process per-vCPU events.
/// - Calling [`EventDistributor::tick()`](crate::event_controller::EventDistributor::tick)
///   to tick peripherals and route interrupts. For stride-based execution this
///   happens once per round. Custom executors should call it roughly per-stride
///   but can be modified according to their use case.
/// - Updating time accounting:
///   - [`vcpu.time.record_stride(&report, stride, wall)`](super::time::VcpuTime::record_stride)
///     after each per-vCPU `cpu.execute` call.
///   - [`core.time.advance(stride)`](super::time::ProcessorTime::advance) once per
///     round before constructing the
///     [`GlobalDelta`](super::time::GlobalDelta) passed to `EventDistributor::tick`.
///
/// ## When to use
///
/// Use `CustomExecutor` when you need to:
/// - Interleave execution with external I/O (e.g. a GDB client)
/// - Run execution in a loop controlled by an external framework (e.g. a fuzzer harness)
/// - Implement execution patterns that don't fit the stride model
///
pub trait CustomExecutor: Send {
    /// Run the custom execution loop.
    ///
    /// Called after emulation setup (plugin/EC lifecycle events) and before emulation teardown.
    /// The implementor has full control over how `vcpus` are executed.
    fn execute(
        &mut self,
        vcpus: &mut PerVcpuSlice<VcpuCore>,
        core: &mut ProcessorCore,
        plugins: &mut Plugins,
        constraints: &ExecutionConstraintConcrete,
    ) -> Result<Vec<EmulationReport>, UnknownError>;

    fn init(&mut self, _proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        Ok(())
    }

    /// Perform any pre-emulation setup, called once per call to `proc.start()`.
    ///
    /// Should call or perform duties of [`emulation_setup()`].
    fn emulation_setup(
        &mut self,
        vcpus: &mut PerVcpuSlice<VcpuCore>,
        core: &mut ProcessorCore,
        plugins: &mut Plugins,
    ) -> Result<(), UnknownError> {
        emulation_setup(vcpus, core, plugins)
    }

    /// Perform any post-emulation teardown, called once per call to `proc.start()`.
    ///
    /// Should call or perform duties of [`emulation_teardown()`].
    fn emulation_teardown(
        &mut self,
        vcpus: &mut PerVcpuSlice<VcpuCore>,
        core: &mut ProcessorCore,
        plugins: &mut Plugins,
    ) -> Result<(), UnknownError> {
        emulation_teardown(vcpus, core, plugins)
    }
}
