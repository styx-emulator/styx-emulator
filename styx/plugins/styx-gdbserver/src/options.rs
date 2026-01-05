// SPDX-License-Identifier: BSD-2-Clause

/// How many instructions to segment "epoch"'s with by default.
const CPU_EPOCH_SIZE_DEFAULT: u64 = 1024;

/// Toggle the tick and IRQ handling during debugger steps.
///
/// See [`GDBOptions::step_irqs`] for more information.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub enum StepIRQs {
    Enabled,
    #[default]
    Disabled,
}

/// Modify the GDB Server's behavior.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GDBOptions {
    /// Toggles IRQs during GDB Step.
    ///
    /// This is analogous to qemu's `qqemu.sstep`.
    /// The default setting of [StepIRQs::Disabled] will not tick peripherals or call
    /// [`EventControllerImpl::next()`](styx_core::event_controller::EventControllerImpl::next()).
    /// Setting this to [StepIRQs::Enabled] will enable these during stepping.
    /// The frequency of ticking is set by [`GDBOptions::cpu_epoch`].
    pub step_irqs: StepIRQs,
    /// How many instructions to run before pausing execution to handle IRQs and GDB input.
    ///
    /// The default is `1024`.
    /// The general tradeoff is larger epoch means faster execution but slower to activate IRQs
    /// and tick peripherals.
    pub cpu_epoch: u64,
}
impl Default for GDBOptions {
    fn default() -> Self {
        GDBOptions {
            step_irqs: StepIRQs::default(),
            cpu_epoch: CPU_EPOCH_SIZE_DEFAULT,
        }
    }
}
