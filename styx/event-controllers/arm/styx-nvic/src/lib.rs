// SPDX-License-Identifier: BSD-2-Clause
//! Emulation of ARM Cortex-M NVIC
//!
//! Max number of external interrupts supported is 496
//!
//! Exception numbers 1-15 are reserved for internal interrupts. (IRQn -16 to -1)
//!
//! Exception Priorities:
//!     - Lower numbers mean higher priority.
//!     - Reset, NMI, and HardFault (exceptions 1,2,3) have fixed priorities of -3, -2, and -1
//!     - There are three numbers to consider when looking at priorities
//!         - Group priority (preemption priority)
//!         - Sub-priority
//!         - Exception number
//!     - If two exceptions have the same group priority then sub-priority is used to break the tie, if both are same then exception number is used.
//!     - If an exception is active, only another exception with a higher group priority can preempt it.
//!
//! **Registers we care about**:
//! Address                 | Name                    | Type |  Reset      | Description
//! ---------------------------------------------------------------------------------------------------
//! 0xE000E004              | ICTR                    | RO   | -           | Interrupt Controller Type Register, ICTR
//! 0xE000EF00              | STIR                    | WO   | -           | Software Triggered Interrupt Register
//! 0xE000ED0C              | AIRCR                   | RW   |             | Application Interrupt and Reset Control Register, AIRCR
//! 0xE000E100 - 0xE000E11C | NVIC_ISER0 - NVIC_ISER7 | RW   | 0x00000000  | Interrupt Set-Enable Registers
//! 0xE000E180 - 0xE000E19C | NVIC_ICER0 - NVIC_ICER7 | RW   | 0x00000000  | Interrupt Clear-Enable Registers
//! 0xE000E200 - 0xE000E21C | NVIC_ISPR0 - NVIC_ISPR7 | RW   | 0x00000000  | Interrupt Set-Pending Registers
//! 0xE000E280 - 0xE000E29C | NVIC_ICPR0 - NVIC_ICPR7 | RW   | 0x00000000  | Interrupt Clear-Pending Registers
//! 0xE000E300 - 0xE000E31C | NVIC_IABR0 - NVIC_IABR7 | RO   | 0x00000000  | Interrupt Active Bit Register
//! 0xE000E400 - 0xE000E4EC | NVIC_IPR0 - NVIC_IPR59  | RW   | 0x00000000  | Interrupt Priority Register
//! 0xE000ED18              | SHPR1                   | RW   | 0x00000000  | System Handler Priority Register 1, SHPR1
//! 0xE000ED1C              | SHPR2                   | RW   | 0x00000000  | System Handler Priority Register 2, SHPR2
//! 0xE000ED20              | SHPR3                   | RW   | 0x00000000  | System Handler Priority Register 3, SHPR3
//! 0xE000ED24              | SHCSR                   | RW   | 0x00000000  | System Handler Control and State Register, SHCSR
//! 0xE000EF34              | FPCCR                   | RW   | -a          | Floating Point Context Control Register, FPCCR
//!
//! **ICTR**:
//! - Provides info about the NVIC
//! - bits`[3:0]` = INTLINESNUM
//! - The total number of interrupt lines supported by an implementation = 32*(INTLINESNUM + 1)
//! - Determines the number of implemented NVIC registers.
//!
//! **STIR**:
//! - Writing INTID = (exception # - 16) into bits`[8:0]` is the same as setting the corresponding ISPR bit.
//!
//! **AIRCR**:
//! - bits`[31:16]` on reads returns 0xFA05, writes of anything other than 0x05FA are ignored
//! - bit`[15]` RO, indicates system memory endianness (0 = little endian)
//! - *bits`[10:8]` resets to 0b000, indicates priority grouping
//! - bit`[2]` system reset request
//! - *bit`[1]` WO, clears all active state info for fixed and configurable exceptions
//! - bit`[0]` writing a 1 to this bit causes a local system reset
//!
//! **NVIC_ISER**:
//! - Enables or shows state of interrupt
//! - Writing a 1 enables an interrupt, writing a 0 does nothing
//!
//! **NVIC_ICER**:
//! - Disables or shows state of interrupt
//! - Writing a 1 disables an interrupt, writing a 0 does nothing
//!
//! **NVIC_ISPR**:
//! - Set pending status for interrupt
//! - Writing 0 does nothing
//!
//! **NVIC_ICPR**:
//! - Clear pending status for interrupt
//! - Writing 0 does nothing
//!
//! **NVIC_IABR**:
//! - Shows if interrupt is active
//!
//! **NVIC_IPR**:
//! - Set or read interrupt priorities
//! - Each register has 4, 8-bit fields which each correspond to a single interrupt
//!
//! **SHPR1**:
//! - set or return priority for system handlers 4-7
//!
//! **SHPR2**:
//! - set or return priority for system handlers 8-11
//!
//! **SHPR3**:
//! - set or return priority for system handlers 12-15
//!
//! **SHCSR**:
//! - controls and provides the active and pending status of system exceptions
//!
//! **FPCCR**:
//! - holds some flags needed during exception entry/exit to determine FP stuff
//! - specifically we care about bit 30 LSPEN flag and bit 0 LSPACT flag
//!
//! **Exception Return Behavior**:
//! If the cpu is in handler mode, loading a value of 0xFXXXXXXX into the PC triggers an exception return.
//!
//! EXC_RETURN | Target mode  | Stack | Frame type
//! ------------------------------------------------------
//! 0xFFFFFFE1 | Handler mode | MSP   | Extended
//! 0xFFFFFFE9 | Thread mode  | MSP   | Extended
//! 0xFFFFFFED | Thread mode  | PSP   | Extended
//! 0xFFFFFFF1 | Handler mode | MSP   | Basic
//! 0xFFFFFFF9 | Thread mode  | MSP   | Basic
//! 0xFFFFFFFD | Thread mode  | PSP   | Basic
//!
//! The NVIC maps a chunk of memory at 0xffff_f000 with size 0x1000 to deal with these return values.
use binary_heap_plus::{BinaryHeap, MinComparator};
use consts::*;
use styx_core::cpu::arch::arm::ArmRegister;
use styx_core::event_controller::*;
use styx_core::memory::MemoryPermissions;
use styx_core::prelude::*;
use styx_core::sync::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU8, Ordering};
use styx_core::sync::sync::{Arc, Mutex, RwLock};
use thiserror::Error;
use tracing::{debug, error, trace, warn};

mod hooks;

type LatchedEvents<T> = Arc<Mutex<BinaryHeap<T, MinComparator>>>;

mod consts {
    #![allow(unused)]
    use super::{ArmRegister, ExceptionNumber};
    /// Max number of events, currently only used to pre-allocate somethings.
    pub const CEC_MAX_EVENTS: usize = 256;

    pub const VTOR_ADDR: u64 = 0xE000_ED08;
    pub const AIRCR_ADDR: u64 = 0xE000_ED0C;
    pub const FPCCR_ADDR: u64 = 0xE000_EF34;
    pub const CCR_ADDR: u64 = 0xE000_ED14;
    pub const STIR: u64 = 0xE000_EF00;
    pub const ISER_BASE: u64 = 0xE000_E100;

    // the registers which get saved to the stack upon entering an ISR
    pub const BASE_CONTEXT_REGISTER_SET: [ArmRegister; 7] = [
        ArmRegister::R0,
        ArmRegister::R1,
        ArmRegister::R2,
        ArmRegister::R3,
        ArmRegister::R12,
        ArmRegister::Lr,
        ArmRegister::Pc,
    ];

    // registers which get saved if the FP extension is present and active
    pub const FP_CONTEXT_REGISTER_SET: [ArmRegister; 17] = [
        ArmRegister::S0,
        ArmRegister::S1,
        ArmRegister::S2,
        ArmRegister::S3,
        ArmRegister::S4,
        ArmRegister::S5,
        ArmRegister::S6,
        ArmRegister::S7,
        ArmRegister::S8,
        ArmRegister::S9,
        ArmRegister::S10,
        ArmRegister::S11,
        ArmRegister::S12,
        ArmRegister::S13,
        ArmRegister::S14,
        ArmRegister::S15,
        ArmRegister::Fpscr,
    ];

    pub const NVIC_ICSR_ADDRESS: u32 = 0xE000ED04;

    pub const RESET_IRQN: ExceptionNumber = -15;
    pub const NMI_IRQN: ExceptionNumber = -14;
    pub const HARDFAULT_IRQN: ExceptionNumber = -13;
    pub const MEMMANAGE_IRQN: ExceptionNumber = -12;
    pub const BUSFAULT_IRQN: ExceptionNumber = -11;
    pub const USAGEFAULT_IRQN: ExceptionNumber = -10;
    pub const SVCALL_IRQN: ExceptionNumber = -5;
    pub const PENDSV_IRQN: ExceptionNumber = -2;

    pub const SHPR_BASE: u64 = 0xE000_ED18;
    pub const SHPR_END: u64 = 0xE000_ED20;

    pub const SHCSR_ADDR: u64 = 0xE000_ED24;
}

#[derive(Debug, Error)]
pub enum NvicError {
    #[error("No periphal for IRQ{0}")]
    EmptyIrq(ExceptionNumber),
}

#[derive(PartialEq, Eq)]
enum CPUMode {
    Handler,
    Thread,
}

#[derive(PartialEq, Eq, Default, Debug, Clone, Copy)]
struct Exception {
    pub irqn: ExceptionNumber,
    enabled: bool,
    pub pending: bool,
    pub active: bool,
    always_enabled: bool,
    has_fixed_priority: bool,
    preempt_priority: i16,
    sub_priority: u8,
}

impl Ord for Exception {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.preempt_priority
            .cmp(&other.preempt_priority)
            .then_with(|| self.sub_priority.cmp(&other.sub_priority))
            .then_with(|| self.irqn.cmp(&other.irqn))
    }
}
impl PartialOrd for Exception {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Exception {
    fn set_priority(&mut self, p: u8, grouping: u8) {
        if self.has_fixed_priority {
            return;
        }

        self.preempt_priority = (p >> grouping).into();
        self.sub_priority = 2_u8.pow(grouping as u32) - 1;

        trace!(
            "Setting IRQ_{}: group priority={}, sub-priority={}",
            self.irqn,
            self.preempt_priority,
            self.sub_priority
        );
    }

    fn set_enabled(&mut self, status: bool) {
        if self.always_enabled {
            self.enabled = true;
        } else {
            self.enabled = status;
        }
    }
}

/// A struct to keep track of the misc flags used to modify the NVIC's behavior
#[derive(Debug)]
pub struct NVICFlags {
    // is the floating-point (fp) extension implemented for this device
    has_fp_ext: bool,
    // is the FP extension active in the current context
    ctl_fpca: bool,
    // determines if stack is 4 or 8 byte aligned on exception entry (false == 4 byte)
    ccr_stkalign: bool,
    // defines which stack to use (false=SP_main, true=SP_process in thread mode)
    ctl_spsel: bool,
    // enables lazy context save of FP state
    fp_lspen: bool,
    // is lazy fp save active
    fp_lspact: bool,
    // controls if cpu can enter thread mode with exceptions active
    ccr_nonbasethrdena: bool,
}

impl Default for NVICFlags {
    fn default() -> Self {
        Self {
            has_fp_ext: true,
            ctl_fpca: true,
            ccr_stkalign: true,
            ctl_spsel: false,
            fp_lspen: true,
            fp_lspact: false,
            ccr_nonbasethrdena: false,
        }
    }
}

/// emulation of a Nested Vectored Interrupt Controller
pub struct Nvic {
    /// The current operating mode of the processor
    cpu_mode: RwLock<CPUMode>,

    /// The current pending events, sorted properly by group priority, sub priority, and irqn
    latched_events: LatchedEvents<Exception>,

    /// is the [`Nvic`] currently executing an interrupt
    executing_interrupt: AtomicBool,

    exceptions: RwLock<[Exception; 496]>,

    /// Current vector table offset
    vector_table_offset: AtomicU32,

    /// a stack to hold the current execution priority
    current_priority: Mutex<Vec<i16>>,

    /// determines the split between group priority and sub-priority
    priority_grouping: AtomicU8,

    // defines the largest IRQn available
    max_irq: AtomicI32,

    flags: Mutex<NVICFlags>,

    current_irqn: Option<ExceptionNumber>,
}

impl Default for Nvic {
    fn default() -> Self {
        let mut latched = BinaryHeap::new_min();
        latched.reserve(CEC_MAX_EVENTS);

        // default behaviour is fine for almost all interrupts
        let mut exceptions = std::array::from_fn(|_| Exception::default());
        for (i, e) in exceptions.iter_mut().enumerate() {
            e.irqn = i as i32 - 15;
        }

        // setting up the system exceptions with custom behaviour (always enabled, fixed priority, etc.)
        // Reset
        exceptions[0].preempt_priority = -3;
        exceptions[0].enabled = true;
        exceptions[0].always_enabled = true;
        exceptions[0].has_fixed_priority = true;
        // NMI
        exceptions[1].preempt_priority = -2;
        exceptions[1].enabled = true;
        exceptions[1].always_enabled = true;
        exceptions[1].has_fixed_priority = true;
        // Hardfault
        exceptions[2].preempt_priority = -1;
        exceptions[2].enabled = true;
        exceptions[2].always_enabled = true;
        exceptions[2].has_fixed_priority = true;
        // SVCall
        exceptions[10].enabled = true;
        exceptions[10].always_enabled = true;
        // PendSV
        exceptions[13].enabled = true;
        exceptions[13].always_enabled = true;
        // SysTick
        exceptions[14].enabled = true;
        exceptions[14].always_enabled = true;

        Self {
            latched_events: Arc::new(Mutex::new(latched)),
            executing_interrupt: AtomicBool::new(false),
            vector_table_offset: AtomicU32::new(0),
            exceptions: RwLock::new(exceptions),
            cpu_mode: RwLock::new(CPUMode::Thread),
            current_priority: Mutex::new(vec![i16::MAX]),
            priority_grouping: AtomicU8::new(0),
            max_irq: AtomicI32::new(496),
            flags: Mutex::new(NVICFlags::default()),
            current_irqn: None,
        }
    }
}

impl EventControllerImpl for Nvic {
    fn next(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        _peripherals: &mut Peripherals,
    ) -> Result<InterruptExecuted, UnknownError> {
        let mut event_queue = self.latched_events.lock().unwrap();
        trace!("Event queue: {event_queue:?}");

        // if there are events in the queue then grab the next
        // valid event and attempt to execute it
        if let Some(event) = self.next_valid(&mut event_queue) {
            let irqn = event.irqn;
            debug!("Handling event: {irqn}");

            // get the exception data state from the exception table
            // so we can check if the event is able to execute given
            // the current execution mask and to preempt the current
            // executing interrupt (if applicable)
            let exception = self.exceptions.read().unwrap()[(irqn + 15) as usize];
            let priority = exception.preempt_priority;

            // check if the incoming interrupt + priority is masked
            if !self.check_interrupt_unmasked(cpu, irqn, priority) {
                return Ok(InterruptExecuted::NotExecuted);
            }

            // attempt to grab the interrupt execution lock and attempt
            // to preempt the current executing interrupt if necessary
            if !self.interrupt_begin(priority) {
                return Ok(InterruptExecuted::NotExecuted);
            }

            // we now have set that we are executing an interrupt, so we
            // can now pop the event off the queue to act on it
            _ = event_queue.pop().with_context(|| "no event on queue");

            // we no longer need the lock, drop it
            std::mem::drop(event_queue);

            // perform all the actions for the target to actually execute
            // the interrupt
            self.execute(irqn, cpu, mmu)
                .with_context(|| "failed to execute queued interrupt")
        } else {
            // no ISR was inserted
            Ok(InterruptExecuted::NotExecuted)
        }
    }

    /// Latches an event into the event queue, and sets the internal
    /// interrupt status to pending
    ///
    /// NOTE: locks `self.latched_events` and `self.exceptions`(write) to
    ///      ensure that the event is valid and can be latched
    fn latch(&mut self, evt: ExceptionNumber) -> Result<(), ActivateIRQnError> {
        let max = self.max_irq.load(Ordering::Acquire);
        if evt > max {
            warn!("attempting to latch event with irqn greater than the max allowed event number");
            return Err(ActivateIRQnError::InvalidIRQn(evt));
        }

        let mut events = self.latched_events.lock().unwrap();

        // if the event is already on the heap then don't add another
        if events.iter().any(|e: &Exception| e.irqn == evt) {
            trace!("event is already on heap, not adding a duplicate.");
            return Ok(());
        }

        // set event status to pending
        self.exceptions.write().unwrap()[(evt + 15) as usize].pending = true;

        debug!("Latching EVT: {}", evt);

        // get the corresponding priority and push that onto the heap
        events.push(self.exceptions.read().unwrap()[(evt + 15) as usize]);
        Ok(())
    }

    /// Executes the provided interrupt
    ///
    /// - This function is called when an interrupt is triggered and the NVIC
    ///   needs to execute the interrupt handler.
    /// - This function assumes that the interrupt is valid and that the interrupt
    ///   is enabled and pending, and not masked by the current priority mask.
    ///
    /// This function will:
    /// - Set the interrupt as active
    /// - Call the pre-event hook for the peripheral associated with the interrupt
    /// - Push the ISR context onto the stack
    /// - Set the IPSR register to the interrupt number
    /// - Set the PC to the vector address for the interrupt
    /// - Emit a `styx_trace` interrupt ISR entry event
    fn execute(
        &mut self,
        irqn: ExceptionNumber,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Result<InterruptExecuted, ActivateIRQnError> {
        // set active
        self.activate_interrupt(irqn);

        let new_pc = self.vector_address(mmu, irqn);

        // push ISR context -- saves all register state
        // to be restored upon ISR exit
        self.push_stack(cpu, mmu);

        // writes the irq number into the IPSR register
        cpu.write_register(ArmRegister::Ipsr, (irqn + 16) as u32)
            .map_err(UnknownError::from)?;

        debug!("Entering ISR for IRQ_{} @0x{:08x}", irqn, cpu.pc()?);

        // set pc to vector address
        cpu.write_register(ArmRegister::Pc, new_pc | 1)
            .map_err(UnknownError::from)?;

        // update cpu mode
        *self.cpu_mode.write().unwrap() = CPUMode::Handler;

        // emit `styx_trace` interrupt ISR entry event
        strace!(InterruptEvent {
            etype: TraceEventType::INTERRUPT,
            old_pc: cpu.pc()? as u32,
            new_pc,
            interrupt_num: irqn,
            interrupt_type: InterruptType::IsrEntry,
            ..Default::default()
        });

        Ok(InterruptExecuted::Executed)
    }

    fn tick(&mut self, _cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        Ok(())
    }

    fn finish_interrupt(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
    ) -> Option<ExceptionNumber> {
        self.current_irqn
    }

    fn init(&mut self, cpu: &mut dyn CpuBackend, mmu: &mut Mmu) -> Result<(), UnknownError> {
        self.register_hooks(cpu, mmu)?;
        self.reset_state(cpu, mmu)?;

        Ok(())
    }
}

impl Nvic {
    /// call to initialize memory range owned by this peripheral
    fn reset_state(&mut self, cpu: &mut dyn CpuBackend, mmu: &mut Mmu) -> Result<(), UnknownError> {
        *self.cpu_mode.write().unwrap() = CPUMode::Thread;

        // reset mask registers
        cpu.write_register(ArmRegister::Primask, 0_u32).unwrap();
        cpu.write_register(ArmRegister::Basepri, 0_u32).unwrap();
        cpu.write_register(ArmRegister::Faultmask, 0_u32).unwrap();

        // reset registers to base value
        mmu.data().write(VTOR_ADDR).le().value(0_u32)?;
        mmu.data().write(NVIC_ICSR_ADDRESS).le().value(0_u32)?;
        mmu.data().write(SHPR_BASE).bytes(&[0_u8; 16])?;
        mmu.data().write(ISER_BASE).bytes(&[0_u8; 0x4EC])?;

        // clear pending and active exceptions
        self.latched_events.lock().unwrap().clear();
        *self.current_priority.lock().unwrap() = vec![i16::MAX];

        for e in self.exceptions.write().unwrap().iter_mut() {
            e.set_enabled(false);
            e.active = false;
            e.set_priority(0, 0);
        }

        // reset nvic state
        self.vector_table_offset.store(0, Ordering::Release);
        self.executing_interrupt.store(false, Ordering::Release);
        self.priority_grouping.store(0, Ordering::Release);

        Ok(())
    }

    /// this should setup the runtime memory hooks needed by the Nvic
    fn register_hooks(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Result<(), UnknownError> {
        // interrupt callback magics
        // exception handlers will return to these addresses which need code hooks
        let interrupt_callback_start = 0xffff_f000;
        let interrupt_callback_size = 0x0000_1000;
        mmu.memory_map(
            interrupt_callback_start,
            interrupt_callback_size,
            MemoryPermissions::all(),
        )?;

        cpu.mem_write_hook(
            NVIC_ICSR_ADDRESS as u64,
            NVIC_ICSR_ADDRESS as u64 + 4,
            Box::new(hooks::nvic_icsr_write_callback),
        )?;

        cpu.add_hook(StyxHook::Interrupt(Box::new(hooks::interrupt_hook)))?;

        // add a hook to catch writes to the VTOR
        cpu.mem_write_hook(VTOR_ADDR, VTOR_ADDR, Box::new(hooks::vtor_write_callback))?;

        // hook FPCCR register
        cpu.mem_write_hook(FPCCR_ADDR, FPCCR_ADDR + 4, Box::new(hooks::fpccr_w_hook))?;

        // hook CCR register
        cpu.mem_write_hook(CCR_ADDR, CCR_ADDR + 4, Box::new(hooks::ccr_write_hook))?;

        // add a hook to catch writes to the STIR
        cpu.mem_write_hook(STIR, STIR, Box::new(hooks::stir_w_hook))?;

        cpu.mem_write_hook(AIRCR_ADDR, AIRCR_ADDR, Box::new(hooks::aircr_w_hook))?;

        // EXC_RETURN values
        cpu.code_hook(
            0xFFFF_FF00,
            0xFFFF_FFFF,
            Box::new(hooks::return_from_exception),
        )?;

        // add a memory hook for NVIC control registers
        cpu.mem_write_hook(
            0xE000_E100,
            0xE000_ECFC,
            Box::new(hooks::nvic_control_w_hook),
        )?;

        // memory write hooks for SHPR{1,2,3} registers
        cpu.mem_write_hook(SHPR_BASE, SHPR_END, Box::new(hooks::shpr_w_hook))?;

        cpu.mem_write_hook(SHCSR_ADDR, SHCSR_ADDR + 4, Box::new(hooks::shcsr_w_hook))?;

        Ok(())
    }
}

impl Nvic {
    /// Called when guest code triggers a local reset.  Currently only called
    /// via the AIRCR write hook.  Calls the Nvic reset state and jumps to
    /// the reset vector.
    fn reset(&mut self, cpu: &mut dyn CpuBackend, mmu: &mut Mmu) {
        debug!("Guest code triggered a reset.");
        self.reset_state(cpu, mmu).unwrap();

        let new_pc = self.vector_address(mmu, RESET_IRQN);
        cpu.set_pc((new_pc as u64) | 1).unwrap();
    }
    /// Retrieves the next valid interrupt event from the queue
    ///
    /// This function ensures that the enqueued event is still valid given
    /// the current [`Nvic`] flags and context. If the event is no longer
    /// valid, it will be removed from the queue.
    fn next_valid(&self, queue: &mut BinaryHeap<Exception, MinComparator>) -> Option<Exception> {
        // binary heap doesn't have an easy way to remove a specific element, so if the pending/enabled status of an exception
        // is cleared while the exception is waiting on the heap, we can't really remove it quickly so instead
        // we just check the pending/enabled status before executing any interrupt
        while let Some(event) = queue.peek() {
            let irqn = event.irqn;

            // ensure that the current irq it valid given the nvic context
            if !self.is_valid(irqn) {
                debug!("IRQ{irqn} no longer enabled or pending, removing from heap.");
                // event is no longer pending/enabled, remove from heap and don't execute it
                queue.pop().unwrap();
            } else {
                return Some(*event);
            }
        }

        None
    }

    /// Checks if an interrupt on the heap is still valid
    ///
    /// Returns bool if the interrupt is both `pending` and `enabled`
    #[inline]
    pub fn is_valid(&self, irqn: ExceptionNumber) -> bool {
        self.exceptions.read().unwrap()[(irqn + 15) as usize].pending
            && self.exceptions.read().unwrap()[(irqn + 15) as usize].enabled
    }

    /// Checks if an interrupt is not currently masked
    ///
    /// This function checks:
    /// - If the interrupt is blocked by the priority mask
    /// - If the interrupt is blocked by the fault mask
    /// - If the interrupt is blocked by the base priority
    ///
    /// returns false if any of the above statements are true
    #[inline]
    pub fn check_interrupt_unmasked(
        &self,
        cpu: &mut dyn CpuBackend,
        irqn: ExceptionNumber,
        priority: i16,
    ) -> bool {
        let priority_mask = cpu.read_register::<u32>(ArmRegister::Primask).unwrap();
        if priority_mask > 0 && priority >= 0 {
            debug!("IRQ{irqn} blocked by PRIMASK");
            return false;
        }

        let fault_mask = cpu.read_register::<u32>(ArmRegister::Faultmask).unwrap();
        if fault_mask > 0 && priority >= -1 {
            debug!("IRQ{irqn} blocked by FAULTMASK");
            return false;
        }

        let base_priority = cpu.read_register::<u32>(ArmRegister::Basepri).unwrap();
        if base_priority > 0 {
            let req_pri = (base_priority >> self.priority_grouping.load(Ordering::Acquire)) as i16;
            if priority >= req_pri {
                debug!("IRQ{irqn} blocked by BASEPRI: {priority} >= {req_pri}");
                return false;
            }
        }

        true
    }

    /// enables an exception. if the exception was already pending then add it to the heap
    fn enable_interrupt(&mut self, irqn: ExceptionNumber) {
        trace!("enabled IRQ: {irqn}");
        self.exceptions.write().unwrap()[(irqn + 15) as usize].set_enabled(true);

        if self.exceptions.read().unwrap()[(irqn + 15) as usize].pending {
            self.latch(irqn).unwrap();
        }
    }

    /// disable exception and update the corresponding bit in the ISER
    fn disable_interrupt(&self, mmu: &mut Mmu, irqn: ExceptionNumber) {
        trace!("disabled IRQ: {irqn}");
        self.exceptions.write().unwrap()[(irqn + 15) as usize].set_enabled(false);

        if irqn >= 0 {
            // set ISER status
            let reg_num = (irqn) / 32;
            let bit_pos = (irqn) % 32;
            let val = mmu
                .data()
                .read(ISER_BASE + 4 * (reg_num as u64))
                .le()
                .u32()
                .unwrap()
                & !(1 << bit_pos);
            mmu.data()
                .write(ISER_BASE + 4 * reg_num as u64)
                .le()
                .value(val)
                .unwrap();
        }
    }

    /// pend exception, if the exception is also enabled then latch event
    fn set_pending(&mut self, irqn: ExceptionNumber) {
        trace!("set pending IRQ: {irqn}");
        self.exceptions.write().unwrap()[(irqn + 15) as usize].pending = true;

        if self.exceptions.read().unwrap()[(irqn + 15) as usize].enabled {
            self.latch(irqn).unwrap();
        }
    }

    /// Clear pending status
    ///
    /// We don't actually remove events from the binary heap here,
    /// just update the internal store to no longer pend the interrupt
    fn clear_pending(&self, irqn: ExceptionNumber) {
        trace!("clear pending IRQ: {irqn}");
        self.exceptions.write().unwrap()[(irqn + 15) as usize].pending = false;
    }

    /// Checks if the provided interrupt is known to be active
    fn check_interrupt_active(&self, irqn: ExceptionNumber) -> bool {
        debug!(
            "Checking active status for IRQn: {irqn} = {:?}",
            self.exceptions.read().unwrap()[(irqn + 15) as usize].active
        );
        self.exceptions.read().unwrap()[(irqn + 15) as usize].active
    }

    /// Activates the provided interrupt and sets the active flag to true
    fn activate_interrupt(&self, irqn: ExceptionNumber) {
        debug!(
            "Setting IRQn: {irqn} to active, currently active={:?}",
            self.exceptions.read().unwrap()[(irqn + 15) as usize].active
        );
        self.exceptions.write().unwrap()[(irqn + 15) as usize].active = true;
    }

    /// Clears the active status for an interrupt
    fn deactivate_current_interrupt(&self, irqn: ExceptionNumber) {
        debug!("Setting IRQn: {irqn} to inactive");
        self.exceptions.write().unwrap()[(irqn + 15) as usize].active = false;
    }

    /// saves context state
    fn push_stack(&self, cpu: &mut dyn CpuBackend, mmu: &mut Mmu) {
        let flags = self.flags.lock().unwrap();
        let current_mode = self.cpu_mode.read().unwrap();

        let mut framesize: u32 = 0x20;
        let mut force_align = flags.ccr_stkalign;

        // Does this pushed stack have an extended frame?
        let extended_frame;
        if flags.has_fp_ext && flags.ctl_fpca {
            trace!("pusing extended frame");
            framesize = 0x68;
            force_align = true;
            extended_frame = true;
        } else {
            trace!("pusing basic frame");
            extended_frame = false;
        }

        let spmask: u32 = if force_align {
            0xFFFF_FFFB
        } else {
            0xFFFF_FFFF
        };

        let mut frameptr_align: u32 = 0;

        let frameptr: u32 = if flags.ctl_spsel && *current_mode == CPUMode::Thread {
            let mut sp_process = cpu.read_register::<u32>(ArmRegister::Psp).unwrap();
            if force_align {
                frameptr_align = (sp_process & (1 << 2)) >> 2;
            }
            sp_process = (sp_process - framesize) & spmask;
            cpu.write_register(ArmRegister::Psp, sp_process).unwrap();
            sp_process
        } else {
            let mut sp_main = cpu.read_register::<u32>(ArmRegister::Msp).unwrap();

            if force_align {
                frameptr_align = (sp_main & (1 << 2)) >> 2;
            }
            sp_main = (sp_main - framesize) & spmask;
            cpu.write_register(ArmRegister::Msp, sp_main).unwrap();
            sp_main
        };

        let mut context: Vec<u8> = Vec::with_capacity(framesize as usize);

        for r in BASE_CONTEXT_REGISTER_SET {
            context.extend_from_slice(&cpu.read_register::<u32>(r).unwrap().to_le_bytes()[0..]);
        }
        let temp = (cpu.read_register::<u32>(ArmRegister::Xpsr).unwrap() & !(1 << 9))
            | (frameptr_align << 9);
        context.extend_from_slice(&temp.to_le_bytes()[0..]);

        if flags.has_fp_ext && flags.ctl_fpca && !flags.fp_lspen {
            for r in FP_CONTEXT_REGISTER_SET {
                context.extend_from_slice(&cpu.read_register::<u32>(r).unwrap().to_le_bytes()[0..]);
            }
        }

        if flags.has_fp_ext {
            if *current_mode == CPUMode::Handler {
                let lr: u32 = if extended_frame {
                    0xFFFF_FFF1 & !(1 << 4)
                } else {
                    0xFFFF_FFF1
                };
                cpu.write_register(ArmRegister::Lr, lr).unwrap();
            } else {
                let mut lr: u32 = if extended_frame {
                    0xFFFF_FFFD & !(1 << 4)
                } else {
                    0xFFFF_FFFD
                };
                if !flags.ctl_spsel {
                    lr &= !(1 << 2);
                }
                cpu.write_register(ArmRegister::Lr, lr).unwrap();
            }
        } else if *current_mode == CPUMode::Handler {
            cpu.write_register(ArmRegister::Lr, 0xFFFF_FFF1_u32)
                .unwrap();
        } else {
            cpu.write_register(ArmRegister::Lr, 0xFFFF_FFF9_u32)
                .unwrap();
        }

        debug!("Saved stack: frame size: {framesize}, frame ptr: 0x{frameptr:x}, 8 byte stack alignment: {force_align}");

        std::mem::drop(flags);
        // write the context into the stack
        mmu.data().write(frameptr).bytes(&context).unwrap();
    }

    /// restores context state
    fn pop_stack(
        &self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        frame_ptr: u32,
        exc_return: u32,
        returning_irqn: i32,
    ) {
        trace!("pop_stack: frame pointer: 0x{frame_ptr:X}");
        let mut flags = self.flags.lock().unwrap();

        let mut framesize: u32 = 0x20;
        let mut force_align = flags.ccr_stkalign;

        let exc_ret_4 = exc_return & (1 << 4);
        let extended_frame = exc_ret_4 == 0;

        if flags.has_fp_ext && extended_frame {
            trace!("pop_stack: detected extended frame");
            framesize = 0x68;
            force_align = true;
        } else {
            trace!(
                "pop_stack: detected basic frame flags.has_fp_ext: {} extended_frame: {}",
                flags.has_fp_ext,
                extended_frame
            );
        }

        let mut context: [u8; 0x68] = [0; 0x68];

        mmu.data()
            .read(frame_ptr)
            .bytes(&mut context[0..framesize as usize])
            .unwrap();

        let mut i = 0_usize;
        for r in BASE_CONTEXT_REGISTER_SET {
            cpu.write_register(
                r,
                u32::from_le_bytes(context[4 * i..4 * (i + 1)].try_into().unwrap()),
            )
            .unwrap();
            i += 1;
        }
        let new_pc = cpu.pc().unwrap() | 1;
        cpu.set_pc(new_pc).unwrap();
        let temp_xpsr = u32::from_le_bytes(context[28..32].try_into().unwrap());
        cpu.write_register(ArmRegister::Xpsr, temp_xpsr).unwrap();

        if flags.has_fp_ext {
            if extended_frame {
                if flags.fp_lspact {
                    flags.fp_lspact = false;
                } else {
                    i = 0_usize;
                    for r in FP_CONTEXT_REGISTER_SET {
                        cpu.write_register(
                            r,
                            u32::from_le_bytes(
                                context[(32 + 4 * i)..(32 + 4 * (i + 1))]
                                    .try_into()
                                    .unwrap(),
                            ),
                        )
                        .unwrap();
                        i += 1;
                    }
                }
            }
            flags.ctl_fpca = exc_ret_4 != 0;
        }

        let spmask: u32 = if force_align {
            ((temp_xpsr >> 9) & 0x1) << 2
        } else {
            0
        };

        match exc_return & 0xF {
            0b0001 | 0b1001 => {
                let sp_main = cpu.read_register::<u32>(ArmRegister::Msp).unwrap();
                cpu.write_register(ArmRegister::Msp, (sp_main + framesize) | spmask)
                    .unwrap();
                cpu.write_register(ArmRegister::Control, 0u32).unwrap();
            }
            0b1101 => {
                let sp_process = cpu.read_register::<u32>(ArmRegister::Psp).unwrap();
                cpu.write_register(ArmRegister::Psp, (sp_process + framesize) | spmask)
                    .unwrap();
                cpu.write_register(ArmRegister::Control, 0b10u32).unwrap();
            }
            _ => {
                warn!("bad exc_return");
            }
        }
        strace!(InterruptEvent {
            etype: TraceEventType::INTERRUPT,
            old_pc: exc_return,
            new_pc: cpu.pc().unwrap() as u32,
            interrupt_num: returning_irqn,
            interrupt_type: InterruptType::IsrExit,
            ..Default::default()
        });

        debug!("Restored stack: frame size: {framesize}, frame ptr: 0x{frame_ptr:x}, 8 byte stack alignment: {force_align}");
        trace!(
            "Return from exception -> 0x{:X}",
            cpu.read_register::<u32>(ArmRegister::Pc).unwrap()
        );
    }

    fn set_vto(&self, v: u32) {
        self.vector_table_offset.store(v, Ordering::Release);
    }

    /// Checks if it is okay to execute a new interrupt with the
    /// current priority level
    ///
    /// This is performed by doing the following:
    /// - check if [`Nvic`] is active
    /// - check if the [`Nvic`] is currently executing an interrupt
    /// - if not, set it to true and return true
    /// - if it is, check if the new priority is higher than the current priority
    ///   (higher priority means lower number), return true if so else false
    fn interrupt_begin(&self, new_priority: i16) -> bool {
        // if !self.active() {
        //     return false;
        // }

        let mut priority_stack = self.current_priority.lock().unwrap();

        // return information based on if the `nvic` is already
        // executing an interrupt
        match self.executing_interrupt.compare_exchange(
            false,
            true,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                // we weren't already executing an interrupt
                // update current priority
                debug!("No active exceptions, begin.");
                priority_stack.push(new_priority);
                true
            }
            Err(_) => {
                // we are already executing an interrupt, figure out if preemption is possible
                if new_priority < *priority_stack.last().unwrap() {
                    debug!("Exception Pre-empted");
                    priority_stack.push(new_priority);
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Clears the flag that says the [`Nvic`] is currently executing an
    /// interrupt
    #[inline]
    fn interrupt_complete(&self) {
        self.executing_interrupt.store(false, Ordering::Release);
    }

    /// Calculates the address of the desired interrupt vector
    fn vector_address(&self, mmu: &mut Mmu, irq: ExceptionNumber) -> u32 {
        let irqn_vec_offset = 16;
        let vto = self.vector_table_offset.load(Ordering::Acquire) as i32;
        let base = vto + (4 * irqn_vec_offset);
        let new_vector_address = base + (irq * 4);

        debug!("vto: {}, vector address: {}", vto, new_vector_address);
        mmu.data().read(new_vector_address).le().u32().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priorities() {
        let a = Exception {
            preempt_priority: -1,
            sub_priority: 0,
            irqn: 3,
            enabled: false,
            pending: false,
            active: false,
            always_enabled: false,
            has_fixed_priority: false,
        };
        let b = Exception {
            preempt_priority: -2,
            sub_priority: 0,
            irqn: 2,
            enabled: false,
            pending: false,
            active: false,
            always_enabled: false,
            has_fixed_priority: false,
        };
        let c = Exception {
            preempt_priority: -3,
            sub_priority: 0,
            irqn: 1,
            enabled: false,
            pending: false,
            active: false,
            always_enabled: false,
            has_fixed_priority: false,
        };

        let arr = RwLock::new([a, b, c]);

        let mut heap = BinaryHeap::new_min();

        heap.push(arr.read().unwrap()[0]);
        heap.push(arr.read().unwrap()[1]);
        heap.push(arr.read().unwrap()[2]);

        assert_eq!(*heap.peek().unwrap(), c);

        let d = Exception {
            preempt_priority: -3,
            sub_priority: 0,
            irqn: 0,
            enabled: false,
            pending: false,
            active: false,
            always_enabled: false,
            has_fixed_priority: false,
        };

        heap.push(d);

        assert_eq!(*heap.peek().unwrap(), d);
    }

    #[test]
    fn test_sub_priority() {
        let a = Exception {
            preempt_priority: 0,
            sub_priority: 0,
            irqn: 3,
            enabled: false,
            pending: false,
            active: false,
            always_enabled: false,
            has_fixed_priority: false,
        };
        let mut b = Exception {
            preempt_priority: 0,
            sub_priority: 1,
            irqn: 2,
            enabled: false,
            pending: false,
            active: false,
            always_enabled: false,
            has_fixed_priority: false,
        };

        let mut heap = BinaryHeap::new_min();

        heap.push(a);
        heap.push(b);

        assert_eq!(*heap.peek().unwrap(), a);

        heap.clear();

        b.sub_priority = 0;

        heap.push(a);
        heap.push(b);

        assert_eq!(*heap.peek().unwrap(), b);
    }
}
