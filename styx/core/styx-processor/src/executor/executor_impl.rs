// SPDX-License-Identifier: BSD-2-Clause

use log::info;
use styx_cpu_type::TargetExitReason;
use styx_errors::UnknownError;

use crate::{
    core::ProcessorCore, cpu::ExecutionReport, executor::Delta, plugins::collection::Plugins,
};

/// The common interface that all executor implementations need to support.
///
/// Add to a processor using
/// [`ProcessorBuilder::with_executor()`](crate::processor::ProcessorBuilder::with_executor()).
///
/// Implementing this trait allows executors to decide how many instructions, to emulate at a time,
/// when to handle events, when to update the state of peripherals, and when to stop emulation.
///
/// Both `halt_emulation` and `post_stride_processing` take a [`Delta`] representing the number of
/// instructions and time elapsed during execution. It's recommended to forward this to the `tick`
/// events in the event controller, peripherals, and plugins, but an [`ExecutorImpl`] can choose to
/// modify this to change the speed of time.
///
/// ## Included Executors
///
/// A list of [`ExecutorImpl`] included in standard Styx.
///
/// - [`DefaultExecutor`](crate::executor::DefaultExecutor)
/// - [`ConditionalExecutor:lExecutorutor`](crate::executor::ConditionalExecutor)
/// - [`SingleStepExecutor`](crate::executor::SingleStepExecutor)
///
/// ## Execution Behavior
///
/// Below is an overview of the executor loop.
///
/// 1. [`Processor::run()`](crate::processor::Processor::run()) is called to start emulation, this
///    calls `Executor::begin()` and gives control of the [`ProcessorCore`] and [`Plugins`] to the
///    `Executor`.
/// 2. The number of instructions per tick cycle (aka the `stride length`) is found by calling
///    [`ExecutorImpl::get_stride_length()`].
///     - Note that this only happens on the call to start/begin and is not rerun between strides.
/// 3. [`ExecutorImpl::emulation_setup()`] is called. This should call `processor_start()` on the
///    event controller, peripherals, and plugins.
/// 4. The emulation loop is entered. First in the emulation loop,
///    [`ExecutorImpl::valid_emulation_conditions()`] is checked.
/// 5. [`ExecutorImpl::emulate()`] is called. This should call `proc.cpu.execute()`.
/// 6. [`ExecutorImpl::halt_emulation()`] is called with the cpu's [`TargetExitReason`] and the
///    amount of [`Delta`] time spent emulating.
/// 7. [`ExecutorImpl::post_stride_processing()`] is called. This should call `tick()` and `next()`
///    methods.
/// 8. Finally, the execution constraints are checked and emulation exits if either are met.
/// 9. This loop (starting at `4.`) continues until something indicates the processor should stop.
///    After which, [`ExecutorImpl::emulation_teardown()`] is called. There is `processor_stop()`
///    should be called.
///
/// [`ExecutorImpl`] implementations should call `tick()`, `next()`, `processor_start()`, and
/// `processor_stop()` in the correct places to avoid unexpected behaviors. Check the default method
/// code for the [`ExecutorImpl`] methods to see how this is done. You can also use
/// `test::test_executor_events()` to verify your
/// [`ExecutorImpl`] calls all of the required events.
///
pub trait ExecutorImpl: Send {
    /// Determine if emulation should continue, called before each stride is executed.
    #[inline]
    fn valid_emulation_conditions(&mut self, _proc: &mut ProcessorCore) -> bool {
        true
    }

    /// Emulate instruction execution until either `timeout` or `insns`, if provided, are
    /// satisfied. If neither is provided, emulation will attempt to run indefinitely.
    /// Note, this _does not_ insert exception handling or check for halt conditions.
    fn emulate(
        &mut self,
        proc: &mut ProcessorCore,
        insns: u64,
    ) -> Result<ExecutionReport, UnknownError> {
        proc.cpu
            .execute(&mut proc.mmu, &mut proc.event_controller, insns)
    }

    /// Determine if emulation should halt, called at the end of each stride.
    #[inline]
    fn halt_emulation(&mut self, reason: &TargetExitReason, _delta: &Delta) -> bool {
        // something is broken or the host requested a stop
        if reason.fatal() || reason.is_stop_request() {
            info!("Executor exit reason: {reason:?}");
            true
        } else {
            false
        }
    }

    /// Perform any pre-emulation setup, called once per call to `proc.start()`
    #[inline]
    fn emulation_setup(
        &mut self,
        proc: &mut ProcessorCore,
        plugins: &mut Plugins,
    ) -> Result<(), UnknownError> {
        plugins.on_processor_start(proc)?;
        proc.event_controller
            .on_processor_start(proc.cpu.as_mut(), &mut proc.mmu)?;
        Ok(())
    }

    /// Perform any post-emulation teardown, called once per call to `proc.start()`
    #[inline]
    fn emulation_teardown(
        &mut self,
        proc: &mut ProcessorCore,
        plugins: &mut Plugins,
    ) -> Result<(), UnknownError> {
        plugins.on_processor_stop(proc)?;
        proc.event_controller
            .on_processor_stop(proc.cpu.as_mut(), &mut proc.mmu)?;
        Ok(())
    }

    /// Do any post-stride processing, called at the end of each stride.
    ///
    /// This should call `proc.event_controller().next()` to process any pending events and
    /// `proc.event_controller.tick()` to tick peripherals.
    #[inline]
    fn post_stride_processing(
        &mut self,
        proc: &mut ProcessorCore,
        plugins: &mut Plugins,
        delta: &Delta,
    ) -> Result<(), UnknownError> {
        let event_controller = &mut proc.event_controller;
        let cpu = &mut proc.cpu;
        let mmu = &mut proc.mmu;

        event_controller.next(cpu.as_mut(), mmu)?;
        event_controller.tick(cpu.as_mut(), mmu, delta)?;
        plugins.tick(proc)?;

        Ok(())
    }

    /// Returns the implementation specific stride length, i.e. how many instructions or
    /// how frequently we check for events.  Only called once when the [`crate::executor::Executor`] is created.
    #[inline]
    fn get_stride_length(&self) -> u64 {
        1000
    }
}
