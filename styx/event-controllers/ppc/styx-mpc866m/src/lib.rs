// SPDX-License-Identifier: BSD-2-Clause
//! Implementation of the `MPC866M` event controller core
//!
//! # Organization
//!
//! Compared to the "standard" model of Memory Mapped Registers (MMR's),
//! where each peripheral owns its own memory area, allowing us
//! to just implement [`Peripheral`] and [`Peripheral::init`].
//!
//! This target allows global relocation of the MMR's via writing
//! to the `IMMR` internal register using the `mtspr` instruction.
//!
//! ## Hook Routing
//!
//! This changes how we organize the normal tree of peripherals and
//! hooks by passing the memory hook routing logic from the backend,
//! to the `SystemInterfaceUnit`. The `SystemInterfaceUnit` does
//! two things (in addition to its normal MPC8XX level responsibilities):
//! - hook all instruction executions to watch for global state modifiers
//!   like `mtspr IMMR, <reg>`
//! - change the IMMR bank memory hook as needed, and route the hooks to
//!   the respective rust object
//!
#![allow(dead_code, unused_variables)]
use derive_more::Display;
use styx_core::cpu::arch::ppc32::variants::Mpc8xxVariants;
use styx_core::errors::StyxMachineError;
use styx_core::errors::UnknownError;
use styx_core::event_controller::{ActivateIRQnError, InterruptExecuted, Peripherals};
use styx_core::prelude::*;

/// IRQs for the MPC866m event controller
///
/// ## Notes
///
/// There are two different type of exceptions; "synchronous", and
/// "asynchronous" (interrupts). Synchronous exceptions are caused due
/// to the processing of an instruction (not by the instruction semantics
/// itself aka manually asserting an interrupt).
///
/// At the machine level, the order in which certain exceptions will be
/// detected is as follows:
///
/// | Order | Exception Enum | Reason |
/// |-------|----------------|--------|
/// | 1  | [`Mpc866mIRQn::Trace`] | Trace bit asserted |
/// | 2  | [`Mpc866mIRQn::InstructionTlbMiss`] | Instruction MMU TLB miss |
/// | 3  | [`Mpc866mIRQn::InstructionTlbError`] | Instruction MMU protection/translation error |
/// | 4  | [`Mpc866mIRQn::MachineCheck`] | Fetch Error |
/// | 5  | [`Mpc866mIRQn::InstructionBreakpoint`] | Match detection |
/// | 6  | [`Mpc866mIRQn::SoftwareEmulation`] | Attempt to invoke unimplemented feature |
/// | 7  | [`Mpc866mIRQn::Program`] or [`Mpc866mIRQn::Alignment`] or [`Mpc866mIRQn::SystemCall`] | This has an internal sub-ordering: Attempting to execute a privileged instruction, Alignment - Load/Store checking, System call - `sc` instruction, `trap` - trap instruction |
/// | 8  | [`Mpc866mIRQn::DataTlbMiss`] | Data TLB miss |
/// | 9  | [`Mpc866mIRQn::DataTlbError`] | Data TLB Error |
/// | 10 | [`Mpc866mIRQn::MachineCheck`] | Load or Store access error
/// | 11 | [`Mpc866mIRQn::DataBreakpoint`] or [`Mpc866mIRQn::PeripheralBreakpoint`] | Match Detection |
///
/// When multiple exception conditions exist, the highest should be taken, in this ordering:
///
/// | Priority | Exception Type | Reason |
/// |----------|----------------|--------|
/// | 1 | [`Mpc866mIRQn::NonmaskableDevelopmentPort`] | Signal from development port |
/// | 2 | [`Mpc866mIRQn::SystemReset`] | `IRQ0` assertion |
/// | 3 | Synchronous Exceptions (see above)  | Instruction Processing |
/// | 4 | [`Mpc866mIRQn::PeripheralBreakpoint`] or [`Mpc866mIRQn::NonmaskableDevelopmentPort`] | Breakpoint signal from any peripheral |
/// | 5 | [`Mpc866mIRQn::External`] | Signal from the interrupt controller |
/// | 6 | [`Mpc866mIRQn::Decrementer`] | Decrementer request |
#[repr(C)]
#[derive(Debug, Display, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Mpc866mIRQn {
    SystemReset = 1,
    MachineCheck,
    DSI,
    ISI,
    External,
    Alignment,
    Program,
    FloatingPointUnavailable,
    Decrementer,
    SystemCall = 0xC,
    Trace,
    FloatingPointAssist,
    SoftwareEmulation,
    InstructionTlbMiss,
    DataTlbMiss,
    InstructionTlbError,
    DataTlbError,
    DataBreakpoint = 0x1c,
    InstructionBreakpoint,
    PeripheralBreakpoint,
    NonmaskableDevelopmentPort,
}

impl Mpc866mIRQn {
    /// Translates the IRQ into the address of the ISR handler routine offset
    /// for the target, note that this is still going to be rebased off of any
    /// location written to the memory rebasing immr (TODO: write down which
    /// register that is)
    const fn isr_address(&self) -> u64 {
        (*self as u64) * 0x100
    }
}

/// Event Controller + Peripheral Orchestrator for the Mpc8xx
/// Family.
///
/// Note that The MPC8XX line is implemented with 2 discrete
/// processors, and 3 main "units"
/// - System Interface Unit
/// - Embedded MPX8xx Processor Core
/// - 32-bit RISC Controller + Program ROM
pub struct Mpc866mController {
    #[allow(dead_code)]
    family_variant: Mpc8xxVariants,
}

impl Mpc866mController {
    pub fn new(variant: Mpc8xxVariants) -> Self {
        Self {
            family_variant: variant,
        }
    }
    /// Top level method of actual exception insertion into the CPU execution flow
    ///
    /// In general, this target uses registers `SRR0` and `SRR1` to hold the previous
    /// state during exception execution. In the common case the `MSR` bits `IP` do not
    /// change, and the `ME` bits are set to zero, and the `LE` bits are copied from the
    /// `ILE` setting of the interruped execution (if applicable), and other bits are 0.
    /// For specific information see section `6.1.2` and `6.1.3` in the MPC866M family
    /// reference manual
    ///
    /// ## Notes
    ///
    /// At this point the IRQ should have already
    /// been translated from an [`ExceptionNumber`] to an [`Mpc866mIRQn`].
    ///
    /// ### New register state
    /// See the manual for details on MSR's and `SRR1`, `SRR0` is documented
    /// below since our implementation does not necessarily support everything
    ///
    /// What `SRR0` needs to point to after this method:
    ///
    /// | Exception | `SRR0 contents` |
    /// |-----------|-----------------|
    /// | Cold reset [`Mpc866mIRQn::SystemReset`] | `undefined` (implementation 0) |
    /// | Warm reset [`Mpc866mIRQn::SystemReset`] | Address of the next insn (Not implemented yet) |
    /// | [`Mpc866mIRQn::MachineCheck`] | Faulting instruction |
    /// | [`Mpc866mIRQn::DSI`] | Target software defined |
    /// | [`Mpc866mIRQn::ISI`] | Target software defined |
    /// | [`Mpc866mIRQn::External`]| Insn queue buffer defined, in general -- the address of the next insn |
    /// | [`Mpc866mIRQn::Alignment`] | Address of the instruction that caused the exception |
    /// | [`Mpc866mIRQn::Program`] | Address of the instruction that caused the exception |
    /// | [`Mpc866mIRQn::FloatingPointUnavailable`] | Address of the instruction that caused the exception |
    /// | [`Mpc866mIRQn::Decrementer`] | Address of the next instruction |
    /// | [`Mpc866mIRQn::SystemCall`] | Address of the next instruction following the respective `syscall` instruction |
    /// | [`Mpc866mIRQn::Trace`] | Address of the next instruction |
    /// | [`Mpc866mIRQn::FloatingPointAssist`] | N/A - not supported and should emit a software emulation exception |
    /// | [`Mpc866mIRQn::SoftwareEmulation`] | Address of the instruction that caused the exception |
    /// | [`Mpc866mIRQn::InstructionTlbMiss`] | Address of the instruction that caused the exception |
    /// | [`Mpc866mIRQn::DataTlbMiss`] | Address of the instruction that caused the exception |
    /// | [`Mpc866mIRQn::InstructionTlbError`] | Address of the instruction that caused the exception |
    /// | [`Mpc866mIRQn::DataTlbError`] | Address of the instruction that caused the exception |
    /// | [`Mpc866mIRQn::DataBreakpoint`] | Address of the instruction that caused the exception |
    /// | [`Mpc866mIRQn::InstructionBreakpoint`] | Address of the instruction that caused the exception |
    /// | [`Mpc866mIRQn::PeripheralBreakpoint`] | Address of the next instruction |
    /// | [`Mpc866mIRQn::NonmaskableDevelopmentPort`] | Address of the next instruction |
    fn insert_exception(&self, irqn: Mpc866mIRQn) -> Result<(), StyxMachineError> {
        todo!("Mpc866mController::insert_exception");
    }
}

impl EventControllerImpl for Mpc866mController {
    fn next(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        peripherals: &mut Peripherals,
    ) -> Result<InterruptExecuted, UnknownError> {
        Ok(InterruptExecuted::NotExecuted)
    }

    fn latch(&mut self, event: ExceptionNumber) -> Result<(), ActivateIRQnError> {
        todo!("Mpc866mController::latch_event({})", event);
    }

    fn execute(
        &mut self,
        irq: ExceptionNumber,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Result<InterruptExecuted, ActivateIRQnError> {
        todo!()
    }

    fn tick(&mut self, cpu: &mut dyn CpuBackend, mmu: &mut Mmu) -> Result<(), UnknownError> {
        todo!()
    }

    fn finish_interrupt(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Option<ExceptionNumber> {
        None
    }

    fn init(&mut self, cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        Ok(())
    }
}
