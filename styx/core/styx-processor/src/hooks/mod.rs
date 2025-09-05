// SPDX-License-Identifier: BSD-2-Clause
//! Hooks for the Styx emulator.
//!
//! Hooks are the means for peripherals, plugins, MMUs, and users to act on common processor events
//! as they happen, as well as influence execution of the processor.
//!
//! Hooks can be added to structs implementing the [`Hookable`] trait, most notably, the
//!
//! # Hooks API
//!
//! Hooks are added via the [`Hookable`] trait. The core behavior is a single [Hookable::add_hook()]
//! function that takes the [StyxHook] enum representing the new hook object and the address range
//! it is triggered by (if applicable). [Hookable] also provides helper functions such as
//! [Hookable::code_hook()] as shorthands for adding specific hook types.
//!
//! The preferred method for constructing [StyxHook] is using the method constructions e.g.
//! [StyxHook::code()], [StyxHook::memory_write()], etc. These are ergonomic constructors that take
//! rust ranges and any object that impls the correct hook callback trait.
//!
//! [`AddHookError::HookTypeNotSupported`] returned from attempting to add a hook, [`Hookable`]
//! implementers can choose to reject hooks if they are not supported.
//!
//! Each type of hook is defined by a trait with a `call` function. Each call function is passed a
//! mutable reference to the core trinity ([CoreHandle]: see more [crate::core]) as well as any
//! parameters custom to the hook type. Additionally, the call is give a mut reference to itself
//! allowing the hook to carry mutable state between calls.
//!
//! Each hook type is blanket implemented for the FnMut signature that applies to its call function
//! allowing users to pass a closure or function with appropriate signature as a hook without having
//! to manually impl the trait.
//!
//! # Example
//!
//! ```
//! # use styx_processor::processor::{ProcessorBuilder, Processor};
//! # use styx_processor::core::builder::DummyProcessorBuilder;
//! # use styx_errors::UnknownError;
//! use styx_processor::hooks::{StyxHook, CoreHandle, CodeHook};
//!
//! // a simple function with the correct signature is a good way to define a hook
//!
//! // code hook that prints the pc where it got called
//! fn fn_code_hook(mut proc: CoreHandle) -> Result<(), UnknownError> {
//!     // access execution state, use ? to propagate errors
//!     let pc = proc.pc()?;
//!     println!("function code hook hit @ 0x{pc:X}");
//!     Ok(())
//! }
//!
//! // a closure will also work
//! let closure_code_hook = move |proc: CoreHandle| {
//!     println!("closure code hook hit");
//!     Ok(())
//! };
//!
//! // hook callbacks are represented by traits so custom structs with state work too
//! #[derive(Default)]
//! struct HitCountCodeHook {
//!     times_hit: u32
//! }
//! impl CodeHook for HitCountCodeHook {
//!     fn call(&mut self, proc: CoreHandle) -> Result<(), UnknownError> {
//!         self.times_hit += 1;
//!         println!("hit, total: {}", self.times_hit);
//!         Ok(())
//!     }
//! }
//!
//! let builder = ProcessorBuilder::default()
//!     .with_builder(DummyProcessorBuilder)
//!     .add_hook(StyxHook::code(0x1234, HitCountCodeHook::default())) // only triggered on 0x1234
//!     .add_hook(StyxHook::code(0x1000..=0x2000, fn_code_hook)) // use rust ranges
//!     .add_hook(StyxHook::code(.., closure_code_hook)); // even unbounded ranges
//! ```

mod address_range;
mod callbacks;
mod core_handle;
mod hookable;
mod token;

pub use address_range::AddressRange;
pub use callbacks::*;
pub use core_handle::*;
pub use hookable::*;
use styx_cpu_type::arch::backends::ArchRegister;
pub use token::HookToken;

use std::fmt::Debug;

/// Enum containing all possible hooks on a Styx cpu.
///
/// There are three types of hook.
///
/// 1. **Address hooks** that trigger on an operation within a range of
///    addresses
///
/// 2. **Register hooks** that trigger on an operation to a specific register.
///
/// 3. **Event hooks** that trigger indiscriminately when an event happens
///
/// All hooks return a [Result] with [styx_errors::UnknownError] error type. An
/// Err variant returned from a hook will be propagated as a fatal error.
///
/// ## Callback Construction
///
/// ### Quick and Dirty
///
/// Box a function with the correct args.
///
/// ```
/// use styx_processor::hooks::{CoreHandle, StyxHook};
/// use styx_processor::memory::helpers::ReadExt;
/// use styx_errors::UnknownError;
///
/// fn my_memory_read_hook(proc: CoreHandle, address: u64, size: u32, data: &mut [u8]) -> Result<(), UnknownError> {
///     // overwrite data with memory at 0x100.
///     // ? will propagate memory error as fatal
///     proc.mmu.data().read(0x100).bytes(data)?;
///     Ok(())
/// }
///
/// // preferred ergonomic method construction
/// let styx_hook = StyxHook::memory_read(0x1000, my_memory_read_hook);
/// // concrete variant construction
/// let styx_hook = StyxHook::MemoryRead(0x1000.into(), Box::new(my_memory_read_hook));
///
/// ```
/// ### Detailed Use
///
/// Hook callbacks are defined by unique traits (e.g. [CodeHook]). Each trait
/// has a `call()` function that takes a [CoreHandle] and hook specific
/// parameters and returns a Result. Additionally, each handle has a
///
///
///  ### NOTE
///
/// Orderings of multiple hooks executing on the same address are `undefined`
/// and cannot be relied upon.
///
/// See individual variants' documentation for specifics on their API
/// guarantees.
///
#[non_exhaustive]
pub enum StyxHook {
    /// Code hook callback function. Whenever the program counter has a value
    /// inside the [AddressRange], the callback will be executed.
    ///
    /// This callback is executed before the instruction caught has been
    /// executed by the guest.
    Code(AddressRange, Box<dyn CodeHook>),

    /// Basic block hook callback function. Whenever a basic block is entered
    /// the callback will be executed.
    Block(Box<dyn BlockHook>),

    /// Insert a memory protection fault callback function.
    ///
    /// Whenever a memory protection fault is encountered on a memory read or
    /// write in the [AddressRange], the callback will be executed.
    ///
    /// The callback function returns a [Resolution] if the callback has fixed
    /// the problem that caused the target program to error. If the callback
    /// returns [Resolution::Fixed] and the problem persists it will likely
    /// hang. If the callback returns [Resolution::NotFixed] and there are no
    /// other handlers, the backend will consider this a fatal error and exit
    /// the target program to return the proper `TargetExitReason`.
    ///
    ProtectionFault(AddressRange, Box<dyn ProtectionFaultHook>),

    /// Insert an unmapped memory fault callback. Whenever an unmapped memory
    /// fault is encountered on a memory read or write in [AddressRange], the
    /// callback will be executed.
    ///
    /// The callback function returns a [Resolution] if the callback has fixed
    /// the problem that caused the target program to error. If the callback
    /// returns [Resolution::Fixed] and the problem persists it will likely
    /// hang. If the callback returns [Resolution::NotFixed] and there are no
    /// other handlers, the backend will consider this a fatal error and exit
    /// the target program to return the proper `TargetExitReason`.
    ///
    UnmappedFault(AddressRange, Box<dyn UnmappedFaultHook>),

    /// Insert a callback that will be invoked every time the guest performs a
    /// memory read in the [AddressRange].
    ///
    /// This callback is executed after the target issues the read but before
    /// the data is transferred anywhere, giving the hook the ability to modify
    /// the data after the target requests it and before the target receives it.
    /// Simply modify the bytes in the mutable slice passed in the callback.
    ///
    MemoryRead(AddressRange, Box<dyn MemoryReadHook>),

    /// Insert a callback that will be invoked every time the guest performs a
    /// memory write in the [AddressRange].
    ///
    /// This callback is executed before the data written by the guest has been
    /// committed to memory.
    ///
    /// <div class="warning">
    /// Data written to the address that triggered the callback will
    /// not persist after the callback. A workaround is to add a read callback
    /// on the same address and modify the read value from the target address there.
    /// </div>
    ///
    MemoryWrite(AddressRange, Box<dyn MemoryWriteHook>),

    /// Interrupt hook callback function. Whenever an interrupt is
    /// encountered, `callback` will be executed.
    Interrupt(Box<dyn InterruptHook>),

    /// Insert a callback to be called when the target attempts to execute an
    /// invalid instruction.
    ///
    /// The callback returns a [Resolution] to signal to the backend that the
    /// invalid instruction error was fixed in order to continue to attempt to
    /// execute at `pc` or not (eg. mapping in new memory, modify permissions to
    /// allow execution, change pc etc). If no invalid insn callback returns
    /// [Resolution::Fixed], then the backend will propagate the error up to the
    /// return [`styx_cpu_type::TargetExitReason`]. This can be nice to compose
    /// different sets of insn decoders for cpu extensions etc.
    InvalidInstruction(Box<dyn InvalidInstructionHook>),

    /// Hook on a read from a register.
    ///
    /// The hook is given a `&mut RegisterValue` of the read bytes that can be
    /// mutated to change the value read by the cpu backend. The mutated value
    /// will be written to the source-of-truth register store in the cpu backend
    /// as well sp subsequent reads provide the modified value.
    ///
    /// Registers that are an exact alias for a hooked register (same size and
    /// value) *may* be triggered. Exact behavior is determined by the cpu
    /// backend.
    ///
    /// ## Multiple Reads in Single Instruction
    ///
    /// The Register Read hook can fire multiple times in one instruction if the
    /// underlying cpu backend reads multiple times. For example, if the
    /// register is read to copy into another register, and then read again to
    /// set a condition flag.
    ///
    /// This is currently **allowed** behavior but may change in the future.
    RegisterRead(ArchRegister, Box<dyn RegisterReadHook>),
    /// Hook on a write to a register.
    ///
    /// This callback is executed before the data written by the guest has been
    /// committed to the register store.
    ///
    /// <div class="warning"> Data written to the register that triggered the
    /// callback will not persist after the callback. A workaround is to add a
    /// read callback on the same register and modify the read value from the
    /// target register there. </div>
    ///
    /// Registers that are an exact alias for a hooked register (same size and
    /// value) *may* be triggered. Exact behavior is determined by the cpu
    /// backend.
    ///
    /// ## Multiple Writes in Single Instruction
    ///
    /// The Register Write hook can fire multiple times in one instruction if
    /// the underlying cpu backend reads multiple times.
    ///
    /// This is currently **allowed** behavior but may change in the future.
    RegisterWrite(ArchRegister, Box<dyn RegisterWriteHook>),
}
impl Debug for StyxHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StyxHook::Code(range, _hook) => write!(f, "CodeHook({range:X?})"),
            StyxHook::Block(_hook) => write!(f, "BlockHook"),
            StyxHook::ProtectionFault(range, _hook) => {
                write!(f, "ProtectionFault({range:X?})")
            }
            StyxHook::UnmappedFault(range, _hook) => {
                write!(f, "UnmappedFault({range:X?})")
            }
            StyxHook::MemoryRead(range, _hook) => {
                write!(f, "MemoryRead({range:X?})")
            }
            StyxHook::MemoryWrite(range, _hook) => {
                write!(f, "MemoryWrite({range:X?})")
            }
            StyxHook::Interrupt(_hook) => {
                write!(f, "Interrupt")
            }
            StyxHook::InvalidInstruction(_hook) => {
                write!(f, "InvalidInstruction")
            }
            StyxHook::RegisterRead(register, _hook) => {
                write!(f, "RegisterRead({register})")
            }
            StyxHook::RegisterWrite(register, _hook) => {
                write!(f, "RegisterWrite({register})")
            }
        }
    }
}

impl StyxHook {
    /// Construct a code hook. Whenever the program counter has a value
    /// inside the passed `range`, the callback will be executed.
    ///
    /// This callback is executed before the instruction caught has been
    /// executed by the guest.
    ///
    /// ```
    /// use styx_processor::hooks::{CoreHandle, StyxHook};
    /// use styx_errors::UnknownError;
    ///
    /// fn my_code_hook(mut proc: CoreHandle) -> Result<(), UnknownError> {
    ///     // do hook things
    ///     let pc = proc.pc()?;
    ///     println!("pc: 0x{pc:X}");
    ///     Ok(())
    /// }
    ///
    /// let code_hook = StyxHook::code(0x1000..0x2000, my_code_hook);
    /// ```
    pub fn code(range: impl Into<AddressRange>, hook: impl CodeHook + 'static) -> Self {
        let range = range.into();
        Self::Code(range, Box::new(hook))
    }

    /// Construct a memory read hook.
    ///
    /// The callback will be invoked every time the guest performs a memory read in the `range`. The
    /// hook has the opportunity to modify the read data by modifying the mutable slice `data`
    /// passed to the hook.
    ///
    /// This callback is executed after the target issues the read but before the data is
    /// transferred anywhere, giving the hook the ability to modify the data after the target
    /// requests it and before the target receives it. Simply modify the bytes in the mutable slice
    /// passed in the callback.
    ///
    /// The `data` slice will be in target endianness and will be the size of the memory operation.
    /// The `size` will be the size of the memory operation done by the processor and match the size
    /// of the `data` slice.
    ///
    /// Changes to these valid bytes of the `data` slice will be reflected in the memory read
    /// operation (i.e. to a register) as well as applied to memory.
    ///
    /// ```
    /// use styx_processor::hooks::{CoreHandle, StyxHook};
    /// use styx_errors::UnknownError;
    ///
    /// fn my_memory_read_hook(mut proc: CoreHandle, address: u64, size: u32, data: &mut [u8]) -> Result<(), UnknownError> {
    ///     // do hook things
    ///     let pc = proc.pc()?;
    ///     println!("pc: 0x{pc:X}");
    ///
    ///     // modify memory being read
    ///     data[0] = 0xDE;
    ///     Ok(())
    /// }
    ///
    /// let memory_read_hook = StyxHook::memory_read(0x1000..0x2000, my_memory_read_hook);
    /// ```
    pub fn memory_read(
        range: impl Into<AddressRange>,
        hook: impl MemoryReadHook + 'static,
    ) -> Self {
        let range = range.into();
        Self::MemoryRead(range, Box::new(hook))
    }

    /// Construct a memory write hook. The callback will be invoked every time the guest performs a
    /// memory write in the `range`.
    ///
    /// This callback is executed before the data written by the guest has been
    /// committed to memory.
    ///
    /// <div class="warning">
    /// Data written to the address that triggered the callback will
    /// not persist after the callback. A workaround is to add a read callback
    /// on the same address and modify the read value from the target address there.
    /// </div>
    ///
    /// The `data` slice will be in target endianness and will be the size of the memory operation.
    /// The `size` will be the size of the memory operation done by the processor and match the size
    /// of the `data` slice.
    ///
    ///  ```
    /// use styx_processor::hooks::{CoreHandle, StyxHook};
    /// use styx_errors::UnknownError;
    ///
    /// fn my_memory_write_hook(
    ///     mut proc: CoreHandle,
    ///     address: u64,
    ///     size: u32,
    ///     data: &[u8],
    /// ) -> Result<(), UnknownError> {
    ///     // do hook things
    ///     let pc = proc.pc()?;
    ///     println!("pc: 0x{pc:X}");
    ///     Ok(())
    /// }
    ///
    /// let memory_write_hook = StyxHook::memory_write(0x1000..0x2000, my_memory_write_hook);
    /// ```
    pub fn memory_write(
        range: impl Into<AddressRange>,
        hook: impl MemoryWriteHook + 'static,
    ) -> Self {
        let range = range.into();
        Self::MemoryWrite(range, Box::new(hook))
    }

    /// Construct an unmapped memory fault callback. Whenever an unmapped memory
    /// fault is encountered on a memory read or write in `range`, the
    /// callback will be executed.
    ///
    /// The callback function returns a [Resolution] if the callback has fixed
    /// the problem that caused the target program to error. If the callback
    /// returns [Resolution::Fixed] and the problem persists it will likely
    /// hang. If the callback returns [Resolution::NotFixed] and there are no
    /// other handlers, the backend will consider this a fatal error and exit
    /// the target program to return the proper `TargetExitReason`.
    ///
    ///  ```
    /// use styx_processor::hooks::{CoreHandle, StyxHook, MemFaultData, Resolution};
    /// use styx_errors::UnknownError;
    ///
    /// fn my_unmapped_fault_hook(
    ///     mut proc: CoreHandle,
    ///     address: u64,
    ///     size: u32,
    ///     fault_data: MemFaultData,
    /// ) -> Result<Resolution, UnknownError> {
    ///     // do hook things
    ///     let pc = proc.pc()?;
    ///     println!("pc: 0x{pc:X}");
    ///     Ok(Resolution::NotFixed)
    /// }
    ///
    /// let unmapped_fault_hook = StyxHook::unmapped_fault(0x1000..0x2000, my_unmapped_fault_hook);
    /// ```
    pub fn unmapped_fault(
        range: impl Into<AddressRange>,
        hook: impl UnmappedFaultHook + 'static,
    ) -> Self {
        Self::UnmappedFault(range.into(), Box::new(hook))
    }

    /// Construct a memory protection fault hook. Whenever a memory protection fault is encountered
    /// on a memory read or write in the `range`, the callback will be executed.
    ///
    /// The callback function returns a [Resolution] if the callback has fixed the problem that
    /// caused the target program to error. If the callback returns [Resolution::Fixed] and the
    /// problem persists it will likely hang. If the callback returns [Resolution::NotFixed] and
    /// there are no other handlers, the backend will consider this a fatal error and exit the
    /// target program to return the proper `TargetExitReason`.
    ///
    /// ```
    /// use styx_processor::hooks::{CoreHandle, StyxHook, MemFaultData, Resolution};
    /// use styx_processor::memory::MemoryPermissions;
    /// use styx_errors::UnknownError;
    ///
    /// fn my_protection_fault_hook(
    ///     mut proc: CoreHandle,
    ///     address: u64,
    ///     size: u32,
    ///     region_permissions: MemoryPermissions,
    ///     fault_data: MemFaultData,
    /// ) -> Result<Resolution, UnknownError> {
    ///     // do hook things
    ///     let pc = proc.pc()?;
    ///     println!("pc: 0x{pc:X}");
    ///     Ok(Resolution::NotFixed)
    /// }
    ///
    /// let protection_fault_hook = StyxHook::protection_fault(0x1000..0x2000, my_protection_fault_hook);
    /// ```
    pub fn protection_fault(
        range: impl Into<AddressRange>,
        hook: impl ProtectionFaultHook + 'static,
    ) -> Self {
        Self::ProtectionFault(range.into(), Box::new(hook))
    }

    /// Construct an interrupt hook callback. Whenever an interrupt is
    /// encountered, the callback will be executed.
    ///
    /// ```
    /// use styx_processor::hooks::{CoreHandle, StyxHook};
    /// use styx_errors::UnknownError;
    ///
    /// fn my_interrupt_hook(mut proc: CoreHandle, interrupt: i32) -> Result<(), UnknownError> {
    ///     // do hook things
    ///     let pc = proc.pc()?;
    ///     println!("pc: 0x{pc:X}");
    ///     Ok(())
    /// }
    ///
    /// let interrupt_hook = StyxHook::interrupt(my_interrupt_hook);
    /// ```
    pub fn interrupt(hook: impl InterruptHook + 'static) -> Self {
        Self::Interrupt(Box::new(hook))
    }

    /// Insert a callback to be called when the target attempts to execute an
    /// invalid instruction.
    ///
    /// The callback returns a [Resolution] to signal to the backend that the
    /// invalid instruction error was fixed in order to continue to attempt to
    /// execute at `pc` or not (eg. mapping in new memory, modify permissions to
    /// allow execution, change pc etc). If no invalid insn callback returns
    /// [Resolution::Fixed], then the backend will propagate the error up to the
    /// return [`styx_cpu_type::TargetExitReason`]. This can be nice to compose
    /// different sets of insn decoders for cpu extensions etc.
    ///
    /// ```
    /// use styx_processor::hooks::{CoreHandle, StyxHook, Resolution};
    /// use styx_errors::UnknownError;
    ///
    /// fn my_invalid_instruction_hook(mut proc: CoreHandle) -> Result<Resolution, UnknownError> {
    ///     // do hook things
    ///     let pc = proc.pc()?;
    ///     println!("pc: 0x{pc:X}");
    ///     Ok(Resolution::NotFixed)
    /// }
    ///
    /// let invalid_instruction_hook = StyxHook::invalid_instruction(my_invalid_instruction_hook);
    /// ```
    pub fn invalid_instruction(hook: impl InvalidInstructionHook + 'static) -> Self {
        Self::InvalidInstruction(Box::new(hook))
    }

    /// Construct a basic block hook. Whenever a basic block is entered
    /// the callback will be executed.
    ///
    /// `address` and `size` contain the starting address and size of the basic block.
    ///
    /// ```
    /// use styx_processor::hooks::{CoreHandle, StyxHook};
    /// use styx_errors::UnknownError;
    ///
    /// fn my_block_hook(mut proc: CoreHandle, address: u64, size: u32) -> Result<(), UnknownError> {
    ///     // do hook things
    ///     let pc = proc.pc()?;
    ///     println!("pc: 0x{pc:X}");
    ///     Ok(())
    /// }
    ///
    /// let block_hook = StyxHook::block(my_block_hook);
    /// ```
    pub fn block(hook: impl BlockHook + 'static) -> Self {
        Self::Block(Box::new(hook))
    }

    /// Construct a hook on a read from a register.
    ///
    /// The hook is given a `&mut RegisterValue` of the read bytes that can be
    /// mutated to change the value read by the cpu backend. The mutated value
    /// will be written to the source-of-truth register store in the cpu backend
    /// as well sp subsequent reads provide the modified value.
    ///
    /// Registers that are an exact alias for a hooked register (same size and
    /// value) *may* be triggered. Exact behavior is determined by the cpu
    /// backend.
    ///
    /// ## Multiple Reads in Single Instruction
    ///
    /// The Register Read hook can fire multiple times in one instruction if the
    /// underlying cpu backend reads multiple times. For example, if the
    /// register is read to copy into another register, and then read again to
    /// set a condition flag.
    ///
    /// This is currently **allowed** behavior but may change in the future.
    ///
    /// ```
    /// use styx_processor::hooks::{CoreHandle, StyxHook};
    /// use styx_errors::UnknownError;
    /// use styx_cpu_type::arch::arm::ArmRegister;
    /// use styx_cpu_type::arch::backends::ArchRegister;
    /// use styx_cpu_type::arch::RegisterValue;
    ///
    /// fn my_register_read_hook(mut proc: CoreHandle,
    ///     register: ArchRegister,
    ///     data: &mut RegisterValue,
    /// ) -> Result<(), UnknownError> {
    ///     // do hook things
    ///     let pc = proc.pc()?;
    ///     println!("pc: 0x{pc:X}");
    ///     Ok(())
    /// }
    ///
    /// let register_read_hook = StyxHook::register_read(ArmRegister::R0, my_register_read_hook);
    /// ```
    pub fn register_read(
        register: impl Into<ArchRegister>,
        hook: impl RegisterReadHook + 'static,
    ) -> Self {
        Self::RegisterRead(register.into(), Box::new(hook))
    }

    /// Construct a hook on a write to a register.
    ///
    /// This callback is executed before the data written by the guest has been
    /// committed to the register store.
    ///
    /// <div class="warning"> Data written to the register that triggered the
    /// callback will not persist after the callback. A workaround is to add a
    /// read callback on the same register and modify the read value from the
    /// target register there. </div>
    ///
    /// Registers that are an exact alias for a hooked register (same size and
    /// value) *may* be triggered. Exact behavior is determined by the cpu
    /// backend.
    ///
    /// ## Multiple Writes in Single Instruction
    ///
    /// The Register Write hook can fire multiple times in one instruction if
    /// the underlying cpu backend reads multiple times.
    ///
    /// This is currently **allowed** behavior but may change in the future.
    ///
    /// ```
    /// use styx_processor::hooks::{CoreHandle, StyxHook};
    /// use styx_errors::UnknownError;
    /// use styx_cpu_type::arch::arm::ArmRegister;
    /// use styx_cpu_type::arch::backends::ArchRegister;
    /// use styx_cpu_type::arch::RegisterValue;
    ///
    /// fn my_register_write_hook(mut proc: CoreHandle,
    ///     register: ArchRegister,
    ///     data: &RegisterValue,
    /// ) -> Result<(), UnknownError> {
    ///     // do hook things
    ///     let pc = proc.pc()?;
    ///     println!("pc: 0x{pc:X}");
    ///     Ok(())
    /// }
    ///
    /// let register_write_hook = StyxHook::register_write(ArmRegister::R0, my_register_write_hook);
    /// ```
    pub fn register_write(
        register: impl Into<ArchRegister>,
        hook: impl RegisterWriteHook + 'static,
    ) -> Self {
        Self::RegisterWrite(register.into(), Box::new(hook))
    }
}
