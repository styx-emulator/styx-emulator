// SPDX-License-Identifier: BSD-2-Clause

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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GDBOptions {
    /// Toggles IRQs during GDB Step.
    ///
    /// This is analogous to qemu's `qqemu.sstep`.
    /// The default setting of [StepIRQs::Disabled] will not tick peripherals or call
    /// the secondary event controller's tick method.
    /// Setting this to [StepIRQs::Enabled] will enable these during stepping.
    /// The frequency of ticking is set by the processor's
    /// [`ConfigRequestedStrideLength`](styx_core::processor::core_configs::ConfigRequestedStrideLength),
    /// which is also how many instructions run before execution pauses to handle IRQs and
    /// GDB input. A larger stride means faster execution but slower to activate IRQs and tick
    /// peripherals.
    pub step_irqs: StepIRQs,
}
