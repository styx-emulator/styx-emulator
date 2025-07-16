// SPDX-License-Identifier: BSD-2-Clause
//! Emulation of ARM Generic Interrupt Controller (GIC)
//!
//! The exception vector table for ARMv7-A contains eight exception vectors (see table B1-3 in the
//! ARMv7-A and ARMv7-R Architecture Reference Manual - ARM DDI 0406C.d).
//!
//! | Exception                     | Offset | Description                                   |
//! |-------------------------------|--------|-----------------------------------------------|
//! | Reset                         | 0x0000 | First instruction executed after reset.       |
//! | Undefined Instruction (Undef) | 0x0004 | Signals usage of an illegal instructions.     |
//! | Supervisor Call (SVC)         | 0x0008 | Issued by software using SVC instruction.     |
//! | Prefetch Abort (PAbt)         | 0x000C | Signals a memory abort on instruction fetch.  |
//! | Data Abort (DAbt)             | 0x0010 | Signals a memory abort on data read or write. |
//! | Hyp Trap                      | 0x0014 | Hypervisor instruction trap                   |
//! | IRQ interrupt                 | 0x0018 | Interrupt Request                             |
//! | FIQ interrupt                 | 0x001C | Fast Interrupt Request                        |
//!
//!   - Any interrupt can be defined as secure or non-secure.
//!   - Any non-secure IRQ goes to the IRQ interrupt vector.
//!   - For any secure IRQ:
//!     - If FIQs are enabled (FIQen bit in the ICPICR Register), go to the FIQ interrupt
//!       vector.
//!     - If FIQs are not enabled, they go to the IRQ interrupt vector (same as a non-secure IRQ).
//!   - the other 6 dispatches are for specific non-IRQ functions. Not sure if we do anything with these yet
//!
//! GIC registers:
//!     Note:
//!         ICC = Interrupt Controller Cpu interface
//!         ICD = Interrupt Controller Distributor
//!
//! Implemented:
//!      - Interrupt Acknowledge Register (ICCIAR)
//!          - The processor reads this register to obtain the interrupt ID.
//!      - Software Generated Interrupt Register (ICDSGIR) - issue SGI
//!
//! TODO:
//!    not needed:
//!      - End of Interrupt Register (ICCEOIR) (we already do this by intercepting execution)
//!
//!   higher priority:
//!      - Interrupt Controller Type Register (ICDICTR)
//!      - Highest Pending Interrupt Register (ICCHPIR)
//!      - CPU Interface Control Register (ICCICR)
//!          - Enables the signaling of interrupts to the target processors.
//!
//!    lower priority:
//!      - Interrupt Priority Mask Register (ICCPMR)
//!      - Binary Point Register (ICCBPR)
//!      - CPU Interface Identification Register (ICCIIDR).
//!      - Distributor Control Register (ICDDCR)
//!      - Distributor Implementer Identification Register (ICDIIDR)
//!      - Interrupt Set-Enable Registers (ICDISERn)
//!      - Interrupt Clear-Enable Registers (ICDICERn)
//!      - Interrupt Set-Pending Registers (ICDISPRn)
//!      - Interrupt Clear-Pending Registers (ICDICPRn)
//!      - Active Bit Registers (ICDABRn)
//!      - Interrupt Priority Registers (ICDIPRn)
//!      - Running Priority Register (ICCRPR)
//!
//!    we'll see:
//!      - Interrupt Configuration Registers (ICDICFRn):
//!          - edge triggered vs. level sensitive
//!          - 1-N or N-N handling
//!      - Interrupt Security Registers (ICDISRn)
//!      - Interrupt Processor Targets Registers (ICDIPTRn)
//!      - Aliased Binary Point Register (ICCABPR)
//!
//! Functionally, the GIC is divided into two parts: the distributor and one or more CPU
//! interfaces.
//!
//! GIC startup execution:
//!   - Get exception vector base address (based on the System Control Register's Vectors bit and
//!     possibly the Vector Base Address Register).
//!   - Get base address for distributor and CPU interface registers (in Configuration Base Address
//!     Register).
//!
//! GIC interrupt handling execution (stuff in parenthesis we're going to just hand wave for now):
//!   1. peripheral interrupt received by GIC
//!   2. (the interrupt state is marked as "pending")
//!   3. (GIC determines if the interrupt is enabled)
//!   4. (for enabled interrupts, the distributor determines the target processor(s) for the
//!      interrupt)
//!   5. (distributor determines highest priority pending interrupt and forwards to the CPU
//!      interface)
//!   6. (CPU interface compares the interrupt priority with the current interrupt priority for the
//!      processor. If the interrupt priority is high enough, the processor will be notified)
//!   7. The preferred return address and cpsr are saved.
//!   8. The CPU interface signals the processor about the interrupt with a ICCIAR write.
//!   9. The processor's program counter is redirected to the proper exception vector.
//!        - If the interrupt is an IRQ, the "secure" state for it is checked:
//!            - If the interrupt is "secure" _and_ if FIQs are enabled (FIQen bit in the ICPICR
//!              Register), the FIQ interrupt vector is invoked.
//!            - Otherwise, the IRQ interrupt vector is invoked.
//!  10. (CPU receives/acknowledges with ICCIAR read - we are just assuming this read for now to
//!      avoid an extra hook)
//!  11. (GIC changes the interrupt state from "pending" to either "active" or "active and pending")
//!  12. (Upon interrupt handling completion, the processor signals completion with a write to the
//!      ICCEOIR register.)
//!  13. (The GIC changes the interrupt state: "active" -> "inactive"; "active and pending' ->
//!      "pending")
//!  14. If there is a pending interrupt of sufficient priority, we return to step 8.
//!  15. If there is no pending interrupt of sufficient priority, the interrupt exception request
//!      ICCIAR is cleared.
//!  16. The execution context is popped off of the stack and normal execution continues.
//!
//! NOTE:
//! * Only interrupts marked "pending" can be signaled to a processor (so "active and pending" will
//!   remain in the queue).
//! * We are not currently handling preemption.

use binary_heap_plus::{BinaryHeap, MinComparator};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use styx_core::{
    arch::arm::ArmRegister,
    event_controller::{ActivateIRQnError, InterruptExecuted},
    prelude::*,
};
use thiserror::Error;
use tracing::{debug, error, trace};

/// Every time PC points to this address, we intercept execution and use it as a trampoline to
/// redirect to either the correct ISR or return back to the previously executing code
const TODO_ISR_RECOVERY_LR_VALUE: u32 = 0x99999999;

/// We need a custom IRQn for exceptions so we can treat everything the same way. The "peripheral"
/// that handles this IRQn is the GIC itself.
const GIC_EXCEPTION_IRQN: ExceptionNumber = -42;

/// The IRQn for a Software Generated Interrupt (SGI) is in the range of 0-15.
const MAX_SGI_IRQN: ExceptionNumber = 15;

/// Interrupt controller CPU interfaces.
const INT_CTRL_CPU_OFFSET: u32 = 0x0100;
/// Interrupt controller distributor.
const INT_CTRL_DIST_OFFSET: u32 = 0x1000;

/// Interrupt Acknowledge Register
/// Read here -> processor acknowledges the interrupt.
const ICCIAR_OFFSET: u32 = 0x00C;
const ICCIAR_RESET: u32 = 0x000003FF;

/// End of Interrupt Register
/// Write here -> processor is done with interrupt handling.
#[allow(dead_code)]
const ICCEOIR_OFFSET: u32 = 0x010;

/// Software Generated Interrupt Register
/// Guest write here -> initiate Software Generated Interrupt (SGI)
const ICDSGIR_OFFSET: u32 = 0xF00;

// XXX: Should we just keep a weak cpu pointer in the structure, since the data is closely tied to
// the cpu, and we need to use it in every method?
#[derive(Debug)]
/// Container for interrupt-related system registers.
struct GicRegisters {
    icciar_addr: u32,
    icdsgir_addr: u32,
}

impl GicRegisters {
    fn new(cba: u32) -> Self {
        let cpu_interface_base = cba + INT_CTRL_CPU_OFFSET;
        let distributor_base = cba + INT_CTRL_DIST_OFFSET;
        let icciar_addr = cpu_interface_base + ICCIAR_OFFSET;
        let icdsgir_addr = distributor_base + ICDSGIR_OFFSET;

        GicRegisters {
            icciar_addr,
            icdsgir_addr,
        }
    }

    fn read_reg_val(&self, mmu: &mut Mmu, addr: u32) -> Result<u32, UnknownError> {
        Ok(mmu.data().read(addr).le().u32()?)
    }

    fn set_icciar_interrupt(&self, mmu: &mut Mmu, interrupt_id: u32) {
        // We need to preserve the initial value.
        let initial_icciar = self.read_reg_val(mmu, self.icciar_addr).unwrap();

        // TODO: Check if we should be setting the CPU ID field.
        // Clear the Interrupt ID bits and set to the new value.
        let new_icciar = (initial_icciar & !ICCIAR_RESET) | (interrupt_id & ICCIAR_RESET);

        // Perform a write to the icciar register.
        mmu.data()
            .write(self.icciar_addr)
            .le()
            .u32(new_icciar)
            .unwrap();
    }

    fn reset_icciar(&self, mmu: &mut Mmu) {
        // We need to preserve the initial value.
        let initial_icciar = self.read_reg_val(mmu, self.icciar_addr).unwrap();

        // Clear the Interrupt ID bits.
        let new_icciar = initial_icciar & !ICCIAR_RESET;

        // Perform a reset to the icciar register.
        mmu.data()
            .write(self.icciar_addr)
            .le()
            .u32(new_icciar)
            .unwrap();
    }
}

// The exception vector table for ARMv7-A.
// | Exception                     | Offset | Description                                   |
// |-------------------------------|--------|-----------------------------------------------|
// | Reset                         | 0x0000 | First instruction executed after reset.       |
// | Undefined Instruction (Undef) | 0x0004 | Signals usage of an illegal instructions.     |
// | Supervisor Call (SVC)         | 0x0008 | Issued by software using SVC instruction.     |
// | Prefetch Abort (PAbt)         | 0x000C | Signals a memory abort on istruction fetch.   |
// | Data Abort (DAbt)             | 0x0010 | Signals a memory abort on data read or write. |
// | Hyp Trap                      | 0x0014 | Hypervisor instruction trap                   |
// | IRQ interrupt                 | 0x0018 | Interrupt Request                             |
// | FIQ interrupt                 | 0x001C | Fast Interrupt Request                        |
#[repr(C)]
#[allow(dead_code)]
#[derive(ToPrimitive, PartialEq, Eq, Clone, Copy, Debug)]
/// Exception vector table representation. The enum value corresponds to the index into the vector
/// table.
/// - Systems with security extensions implemented have secure, non-secure and monitor vector tables.
/// - Systems with virtualization extensions implemented add a hyp vector table. In the hyp vector
///   table, besides the hyp mode entry vector, vectors can only be accessed from hyp mode.
enum ExceptionVector {
    /// Handles reset exceptions. Unused in monitor or hyp vector tables.
    Reset = 0,
    /// Handles undefined instruction exceptions. Unused in monitor or hyp vector tables.
    UndefinedInstruction = 1,
    /// Handles supervisor calls in the secure or non-secure vector tables.
    /// Handles secure monitor calls in the monitor vector table.
    /// Handles hypervisor call in the hyp vector table.
    SupervisorCall = 2,
    /// Handles memory abort exceptions on instruction fetches.
    PrefetchAbort = 3,
    /// Handles memory abort exceptions on data reads or writes.
    DataAbort = 4,
    /// Hyp mode entry in the hyp vector table. Unused in all other vector tables.
    HypervisorTrap = 5,
    /// Interrupt request.
    Irq = 6,
    /// Fast interrupt request.
    Fiq = 7,
}

//#[derive(PartialEq, Eq, Debug)]
#[derive(Debug)]
enum EventType {
    Exception(ExceptionVector),
    Interrupt(ExceptionNumber),
}

/// This is the data container used by the [`GicIsrRecovery`] and holds the register state +
/// interrupt number as well as holds the routines to perform the automatic stack maintinence.
/// According to the reference, `pc` and `cpsr` are saved by the processor, but we also save `lr`
/// since we use it to intercept returns from ISRs.
/// TODO: move the maintinence routines into [`GicIsrRecovery`]
#[derive(Debug)]
struct IsrContext {
    lr: u32,
    pc: u32,
    cpsr: u32,
    evt_num: ExceptionNumber,
}

impl IsrContext {
    fn new(cpu: &mut dyn CpuBackend, evt_num: ExceptionNumber) -> Self {
        IsrContext {
            lr: cpu.read_register::<u32>(ArmRegister::Lr).unwrap(),
            pc: cpu.read_register::<u32>(ArmRegister::Pc).unwrap(),
            cpsr: cpu.read_register::<u32>(ArmRegister::Cpsr).unwrap(),
            evt_num,
        }
    }

    #[allow(dead_code)]
    fn to_bytes(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();

        out.extend_from_slice(&self.cpsr.to_le_bytes()[0..]);
        out.extend_from_slice(&self.pc.to_le_bytes()[0..]);
        out.extend_from_slice(&self.lr.to_le_bytes()[0..]);

        out
    }
}

/// This is used to manage the ISR state machine for entering/ exiting interrupts. In hardware,
/// this seems to be handled by the processor instead of the GIC, but we do it here since it keeps
/// the architecture simple.
/// Overview of exception entry: Arm7-A and Arm7-R TRM section B1.8.3.
/// Saves `pc`, `cpsr` (per the spec) and `lr` (because we abuse it to intercept and redirect
/// execution).
#[derive(Debug, Default)]
struct GicIsrRecovery {
    contexts: Arc<Mutex<Vec<IsrContext>>>,
}

impl GicIsrRecovery {
    /// Save the necessary execution context elements prior to handling an exception.
    fn push_context(&self, cpu: &mut dyn CpuBackend, evt_num: ExceptionNumber) {
        // get the current context
        let context = IsrContext::new(cpu, evt_num);

        // save context
        self.contexts.lock().unwrap().push(context);

        // Save the cpsr to the spsr... not sure if anything uses it, but it is spelled out in the
        // ARM7-A / ARM7-R TRM.
        let cpsr = cpu.read_register::<u32>(ArmRegister::Cpsr).unwrap();
        cpu.write_register(ArmRegister::Spsr, cpsr).unwrap();
    }

    /// Restore the execution context after handling an exception.
    fn pop_context(&self, cpu: &mut dyn CpuBackend) -> ExceptionNumber {
        let context = self.contexts.lock().unwrap().pop().unwrap();

        cpu.write_register(ArmRegister::Lr, context.lr).unwrap();
        cpu.write_register(ArmRegister::Pc, context.pc).unwrap();
        cpu.write_register(ArmRegister::Cpsr, context.cpsr).unwrap();

        context.evt_num
    }

    fn is_recovery_stack_empty(&self) -> bool {
        self.contexts.lock().unwrap().is_empty()
    }
}

#[derive(Debug, Error)]
pub enum GicError {
    #[error("No periphal for IRQ{0}")]
    EmptyIrq(ExceptionNumber),
    #[error("Failed to initialize with given configuration")]
    InitializationFailure,
}

#[derive(Debug)]
struct GicConfig {
    /// Vector Base Address Register
    vba: u32,
}

pub struct Gic {
    /// XXX: In no universe is this correct, for now it does
    /// the job. `Gic` needs to be reworked to take into
    /// account the MMR's that change the priority of interrupts
    /// at runtime.
    latched_events: BinaryHeap<ExceptionNumber, MinComparator>,

    /// is the [`Gic`] currently executing an interrupt
    executing_interrupt: Mutex<bool>,

    /// handle to isr recovery insertion routines
    isr_recovery: Arc<GicIsrRecovery>,

    // We make the registers and config substructures [`LateInit`] since they depend on
    // configuration information that is not available at the time of instantiation.
    /// Registers for interfacing with the guest during interrupts.
    registers: LateInit<GicRegisters>,

    /// Hold configuration information.
    config: LateInit<GicConfig>,
}

/// Max number of events, currently only used to pre-allocate some things.
///
/// NOTE: If this is used for more than emulating ARM Cortex-A9 GIC's then this should be re-worked
/// to become an implementation detail.
const TODO_GIC_CEC_MAX_EVENTS: usize = 1244;

impl Default for Gic {
    fn default() -> Self {
        let mut latched = BinaryHeap::new_min();
        latched.reserve(TODO_GIC_CEC_MAX_EVENTS);

        Self {
            latched_events: latched,
            executing_interrupt: Mutex::new(false),
            isr_recovery: Arc::new(GicIsrRecovery::default()),
            registers: Default::default(),
            config: Default::default(),
        }
    }
}

impl EventControllerImpl for Gic {
    /// For the moment we can get away with only a simple "get the smallest interrupt number and
    /// execute it"
    fn next(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        _peripherals: &mut styx_core::event_controller::Peripherals,
    ) -> Result<styx_core::event_controller::InterruptExecuted, UnknownError> {
        // peek to see if there are events to execute
        let event = self.latched_events.peek();

        // Get the current minimum value in the interrupt min-heap if it exists, else we're done
        // and don't need to do anything. By default, the lowest value is the highest priority.
        if event.is_some() {
            // event is present -- now we need to attempt to grab
            // the interrupt execution lock
            if !self.interrupt_begin() {
                return Ok(InterruptExecuted::NotExecuted);
            }

            // we now own the interrupt executing boolean, so we
            // can now pop the event off the queue
            let evt_num = self.latched_events.pop().unwrap();
            trace!(
                target: "interrupts",
                "{{\"type\": \"interrupts\", \"action\": \"execute\", \"event\": {}}}",
                evt_num
            );

            self.handle_event(cpu, mmu, EventType::Interrupt(evt_num));

            // we inserted an ISR
            Ok(InterruptExecuted::Executed)
        } else {
            // no ISR was inserted
            Ok(InterruptExecuted::NotExecuted)
        }
    }

    fn latch(&mut self, evt: ExceptionNumber) -> Result<(), ActivateIRQnError> {
        trace!("Latching EVT: {}", evt);

        self.latched_events.push(evt);
        Ok(())
    }

    fn execute(
        &mut self,
        _irq: ExceptionNumber,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
    ) -> Result<InterruptExecuted, ActivateIRQnError> {
        Ok(InterruptExecuted::NotExecuted)
    }

    fn finish_interrupt(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
    ) -> Option<ExceptionNumber> {
        None
    }

    fn init(&mut self, _cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        Ok(())
    }
}

// TODO: we shouldn't have to do this?
// Adapted from `unicorn/qemu/target/arm/cpu.h`
#[repr(C)]
#[derive(FromPrimitive, PartialEq, Eq, Clone, Copy, Debug)]
enum UnicornException {
    UndefinedInstruction = 1,
    SoftwareInterrupt = 2,
    PrefetchAbort = 3,
    DataAbort = 4,
    Irq = 5,
    Fiq = 6,
    HypTrap = 12,
    /* Unhandled Unicorn exceptions:
        Bkpt = 7,
        EXCEPTION_EXIT = 8,   /* Return from v7M exception.  */
        KERNEL_TRAP = 9,   /* Jumped to kernel code page.  */
        HVC = 11,   /* HyperVisor Call */
        SMC = 13,   /* Secure Monitor Call */
        VIRQ = 14,
        VFIQ = 15,
        SEMIHOST = 16,   /* semihosting call */
        NOCP = 17,   /* v7M NOCP UsageFault */
        INVSTATE = 18,   /* v7M INVSTATE UsageFault */
        STKOF = 19,   /* v8M STKOF UsageFault */
        LAZYFP = 20,   /* v7M fault during lazy FP stacking */
        LSERR = 21,   /* v8M LSERR SecureFault */
        UNALIGNED = 22,   /* v7M UNALIGNED UsageFault */
    */
}

/// Convert a Unicorn exception into a guest exception and add the event to the event queue.
fn handle_interrupts(proc: CoreHandle, intno: i32) -> Result<(), UnknownError> {
    let gic = proc.event_controller.get_impl::<Gic>()?;

    let native_exception = match FromPrimitive::from_i32(intno) {
        Some(UnicornException::UndefinedInstruction) => {
            debug!("UnicornException::UndefinedInstruction");
            ExceptionVector::UndefinedInstruction
        }
        Some(UnicornException::SoftwareInterrupt) => {
            debug!("UnicornException::SoftwareInterrupt");
            ExceptionVector::SupervisorCall
        }
        Some(UnicornException::PrefetchAbort) => {
            debug!("UnicornException::PrefetchAbort");
            ExceptionVector::PrefetchAbort
        }
        Some(UnicornException::DataAbort) => {
            debug!("UnicornException::DataAbort");
            ExceptionVector::DataAbort
        }
        Some(UnicornException::HypTrap) => {
            debug!("UnicornException::HypTrap");
            ExceptionVector::HypervisorTrap
        }
        // XXX: How will we know the IRQn for Irq and Fiq exceptions?
        Some(UnicornException::Irq) | Some(UnicornException::Fiq) | None => {
            panic!("Unhandled unicorn exception! {intno}")
        }
    };

    // should this be execute?
    // Rather than latch them, we handle these events immediately since Unicorn is blocked.
    gic.handle_event(proc.cpu, proc.mmu, EventType::Exception(native_exception));
    Ok(())
}

/// Code hook that will restore the top of the ISR stack to the current cpu state
fn pop_isr_context(proc: CoreHandle) -> Result<(), UnknownError> {
    let gic = proc.event_controller.get_impl::<Gic>()?;

    // store the current pc
    let old_pc = proc.cpu.pc().unwrap() as u32;

    // this restores the old-old pc (destination/new pc)
    let evt_num = gic.isr_recovery.pop_context(proc.cpu);

    // Clear the Interrupt ID from the ICCIAR.
    gic.registers.reset_icciar(proc.mmu);

    // debug the interrupt IsrExit event
    strace!(InterruptEvent {
        etype: TraceEventType::INTERRUPT,
        old_pc,
        new_pc: proc.cpu.pc().unwrap() as u32,
        interrupt_num: evt_num,
        interrupt_type: InterruptType::IsrExit,
        ..Default::default()
    });

    // popped execution context, now route cleanup hook
    // and relinquish the execution lock
    gic.post_irq_route_hook(evt_num);
    if gic.isr_recovery.is_recovery_stack_empty() {
        gic.interrupt_complete();
    }
    Ok(())
}

fn gic_icdsgir_write_callback(
    proc: CoreHandle,
    _address: u64,
    _size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    // Example of setting the icdsgir in the Altera SDK:
    //   armv7a/hwlib/src/hwmgr/alt_interrupt.c!alt_int_sgi_trigger line 854.
    // XXX: We are ignoring the CPU target list for now.
    let icdsgir = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let sgi_int_id: ExceptionNumber = 0x000F & icdsgir as ExceptionNumber;

    // SGIs are Interrupt IDs 0-15.
    if sgi_int_id > MAX_SGI_IRQN {
        panic!("Received an SGI with an invalid interrupt ID greater than 15.");
    }

    trace!("Latching SGI: interrupt ID {}", sgi_int_id);
    proc.event_controller.latch(sgi_int_id).unwrap();
    let gic = proc.event_controller.get_impl::<Gic>()?;

    // We've handled it behind the scenes, so we clear the register.
    proc.mmu
        .data()
        .write(gic.registers.icdsgir_addr)
        .bytes(&[0u8; 4])
        .unwrap();
    Ok(())
}

impl Peripheral for Gic {
    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        self.register_hooks(proc.core.cpu.as_mut())
    }

    fn name(&self) -> &str {
        "Gic Peripheral"
    }
}

impl Gic {
    /// this should setup the runtime memory hooks needed by the Gic
    fn register_hooks(&self, cpu: &mut dyn CpuBackend) -> Result<(), UnknownError> {
        // When pc hits 0x99999999 (impossible value)
        // we catch it and restore the stack like hardware does
        let isr_address = (TODO_ISR_RECOVERY_LR_VALUE - 1) as u64;
        cpu.code_hook(isr_address, isr_address, Box::new(pop_isr_context))?;

        cpu.mem_write_hook(
            self.registers.icdsgir_addr as u64,
            self.registers.icdsgir_addr as u64,
            Box::new(gic_icdsgir_write_callback),
        )?;

        cpu.intr_hook(Box::new(handle_interrupts))?;

        Ok(())
    }

    /// returns if it is okay to continue executing new interrupt
    fn interrupt_begin(&self) -> bool {
        // if we're already executing an interrupt don't do anything
        let interrupt_execution = self.executing_interrupt.try_lock();

        // Check for the two error cases:
        // - failed to get the lock -- bail
        // - got the lock but we are already executing interrupt -- bail
        if let Ok(mut interrupt_executing) = interrupt_execution {
            if *interrupt_executing {
                return false;
            }

            // there is no current holder of the lock, and
            // there it no current interrupt executing, change that
            // and return true :D
            *interrupt_executing = true;
            true
        } else {
            // error
            false
        }
    }

    fn interrupt_complete(&self) {
        let mut executing = self.executing_interrupt.lock().unwrap();
        *executing = false;
    }

    #[inline]
    fn handle_event(&self, cpu: &mut dyn CpuBackend, mmu: &mut Mmu, event_type: EventType) {
        let evt_num: ExceptionNumber;
        match event_type {
            EventType::Exception(_) => {
                // We use a special IRQn for these, since they are exceptions and are handled
                // directly by the GIC.
                evt_num = GIC_EXCEPTION_IRQN;
            }
            EventType::Interrupt(event_irqn) => {
                evt_num = event_irqn;

                // Put the interrupt ID into the ICCIAR register for the guest. This is only
                // necessary for IRQs and FIQs.
                self.registers.set_icciar_interrupt(mmu, evt_num as u32);
            }
        };

        // Save execution context - to be restored upon ISR exit.
        self.isr_recovery.push_context(cpu, evt_num);

        // Move our magic into LR so that our ISR hw cleanup happens.
        cpu.write_register(ArmRegister::Lr, TODO_ISR_RECOVERY_LR_VALUE)
            .unwrap();

        // Find the address of the appropriate exception vector.
        let new_pc = self.vector_address(event_type);
        trace!("Setting PC to {:#08X}, (EVT{})", new_pc, evt_num);

        // emit `styx_trace` interrupt ISR entry event
        strace!(InterruptEvent {
            etype: TraceEventType::INTERRUPT,
            old_pc: cpu.pc().unwrap() as u32,
            new_pc,
            interrupt_num: evt_num,
            interrupt_type: InterruptType::IsrEntry,
            ..Default::default()
        });

        // Move pc to vector.
        cpu.write_register(ArmRegister::Pc, new_pc).unwrap();
    }

    /// This is called by [`GicIsrRecovery`] to route the "post evt hook"
    /// callbacks to the proper peripheral
    #[inline]
    fn post_irq_route_hook(&self, evt: ExceptionNumber) {
        trace!(target: "interrupts", "{{\"type\": \"interrupts\", \"action\": \"complete\", \"event\": {}}}", evt);
    }

    /// Calculates the address of the desired interrupt vector
    fn vector_address(&self, event_type: EventType) -> u32 {
        let vector_index = match event_type {
            EventType::Exception(exception_id) => exception_id as u32,
            EventType::Interrupt(_) => {
                // TODO: check if this should be an FIQ.
                // If FIQs are enabled (FIQen bit in the ICPICR Register), go to the FIQ interrupt
                // vector.
                ExceptionVector::Irq as u32
            }
        };

        // Index into the exception vector table for the appropriate vector.
        self.config.vba + (vector_index * 4)
    }

    pub fn initialize(&self, vba: u32, cba: u32) -> Result<(), UnknownError> {
        if self.config.init(GicConfig { vba }).is_err() {
            return Err(GicError::InitializationFailure.into());
        }
        if self.registers.init(GicRegisters::new(cba)).is_err() {
            return Err(GicError::InitializationFailure.into());
        }
        Ok(())
    }
}
