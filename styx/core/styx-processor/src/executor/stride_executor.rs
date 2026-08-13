// SPDX-License-Identifier: BSD-2-Clause

use static_assertions::assert_obj_safe;
use styx_errors::UnknownError;

use crate::core::{ProcessorCore, VcpuCore};
use crate::plugins::collection::Plugins;
use crate::processor::{BuildingProcessor, PerVcpuSlice};

use super::time::GlobalDelta;
use super::{emulation_setup, emulation_teardown, HaltFn};

// StrideExecutor must be able to be put in `Box<dyn StrideExecutor>`
assert_obj_safe!(StrideExecutor);

/// Trait that defines the standard stride-based execution loop.
///
/// Implementors configure stride length and halt conditions. The [`Executor`](super::Executor)
/// handles the actual emulate -> tick -> check cycle. Looking for standard executor? You
/// probably want the [`DefaultExecutor`](crate::executor::DefaultExecutor).
///
/// Add to a processor using
/// [`ProcessorBuilder::with_executor()`](crate::processor::ProcessorBuilder::with_executor()).
///
/// ## Included Stride Executors
///
/// - [`DefaultExecutor`](crate::executor::DefaultExecutor)
/// - [`ConditionalExecutor`](crate::executor::ConditionalExecutor)
/// - [`SingleStepExecutor`](crate::executor::SingleStepExecutor)
///
/// ## Execution Behavior
///
/// Below is an overview of the executor loop when using a `StrideExecutor`.
///
/// 1. [`Processor::run()`](crate::processor::Processor::run()) is called to start emulation.
/// 2. The stride length is found by calling [`StrideExecutor::get_stride_length()`].
/// 3. Emulation setup runs: `processor_start()` on the event controller, peripherals, and plugins.
/// 4. The emulation loop is entered. Each iteration:
///    a. The vCPU executes `stride` instructions via `cpu.execute()`.
///    b. [`StrideExecutor::halt_emulation()`] is checked with the cpu's exit reason.
///    c. Post-stride processing runs `tick()` and `next()` on event controllers and peripherals.
///    d. Execution constraints (instruction count, timeout) are checked.
/// 5. After the loop exits, emulation teardown runs: `processor_stop()` on all components.
pub trait StrideExecutor: Send {
    fn init(&mut self, _proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        Ok(())
    }

    /// Supply a custom halt condition evaluated at the end of each stride.
    ///
    /// Called once per vCPU at the start of emulation. Return `None` to use the built-in
    /// default, which stops on fatal exits or host-requested stops.
    fn halt_emulation(&mut self) -> Option<HaltFn> {
        None
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

    /// Returns the implementation specific stride length.
    ///
    /// This is how many instructions or how frequently we check for events.
    /// Only called once when the [`Executor`](crate::executor::Executor) is created.
    ///
    /// Defaults to 1000.
    fn get_stride_length(&self) -> u64 {
        1000
    }

    /// Executor tick
    fn tick(
        &mut self,
        _delta: &GlobalDelta,
        _vcpus: &mut PerVcpuSlice<VcpuCore>,
    ) -> Result<(), UnknownError> {
        Ok(())
    }
}
