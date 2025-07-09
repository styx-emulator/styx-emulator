// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
use std::{any::Any, sync::Arc};

use static_assertions::assert_obj_safe;
use styx_errors::UnknownError;
use thiserror::Error;

use super::{
    callbacks::{CodeHook, ProtectionFaultHook},
    BlockHook, HookToken, InterruptHook, InvalidInstructionHook, MemoryReadHook,
    MemoryReadHookData, MemoryReadHookDataFn, MemoryWriteHook, MemoryWriteHookData,
    MemoryWriteHookDataFn, StyxHook, UnmappedFaultHook,
};

/// Error while adding a hook.
///
/// [Hookable] implementors can choose to not support hook types
/// ([AddHookError::HookTypeNotSupported]).
#[derive(Error, Debug)]
pub enum AddHookError {
    #[error("cpu does not support this hook type")]
    HookTypeNotSupported,
    #[error(transparent)]
    Other(#[from] UnknownError),
}

#[derive(Error, Debug)]
pub enum DeleteHookError {
    #[error("hook with token does not exist")]
    HookDoesNotExist,
    #[error(transparent)]
    Other(#[from] UnknownError),
}

pub type HookUserData = Arc<dyn Any + Send + Sync>;

assert_obj_safe!(Hookable);

/// Able add a [`StyxHook`] through [`Hookable::add_hook()`].
///
/// `Hookable` types do not have to support every type of [`StyxHook`] and can
/// return `Err(AddHookError::HookTypeNotSupported)` instead.
pub trait Hookable {
    /// Add a hook, usually to a [Processor](crate::processor::Processor) or
    /// [CoreHandle](crate::hooks::CoreHandle).
    ///
    /// The preferred method of hook creation is using [`StyxHook`] method constructors.
    ///
    /// ```
    /// use styx_processor::cpu::{CpuBackend, DummyBackend};
    /// use styx_processor::hooks::{Hookable, CoreHandle, StyxHook};
    /// use styx_errors::UnknownError;
    ///
    /// fn my_code_hook(mut proc: CoreHandle) -> Result<(), UnknownError> {
    ///     // do hook things
    ///     let pc = proc.pc()?;
    ///     println!("pc: 0x{pc:X}");
    ///     Ok(())
    /// }
    ///
    /// // this would be a processor or core handle in real styx code
    /// let mut cpu = DummyBackend;
    ///
    /// let code_hook = StyxHook::code(0x1000..0x2000, my_code_hook);
    ///
    /// cpu.add_hook(code_hook)?;
    /// # Ok::<(), styx_errors::UnknownError>(())
    /// ```
    ///
    /// See [`StyxHook`] for more details on the available types hooks and additional ways to
    /// construct and define hook callback.
    ///
    /// Adding a hook is a fallible operation. A cpu backend may choose to not support hook types
    /// indicated with the return value [`Err(AddHookError::HookTypeNotSupported)`](AddHookError::HookTypeNotSupported)
    ///
    /// The returned [`HookToken`] is used to [`Hookable::delete_hook()`].
    fn add_hook(&mut self, hook: StyxHook) -> Result<HookToken, AddHookError>;

    /// Delete a hook from this store using a token given by [`Hookable::add_hook()`].
    ///
    // TODO would it be useful to return the StyxHook?
    fn delete_hook(&mut self, token: HookToken) -> Result<(), DeleteHookError>;

    /// Add a block hook.
    ///
    /// See [StyxHook::block()] for information on block hooks.
    fn block_hook(
        &mut self,
        hook: Box<dyn BlockHook + 'static>,
    ) -> Result<HookToken, AddHookError> {
        self.add_hook(StyxHook::Block(hook))
    }

    /// Add a code hook between addresses `start` and `end` inclusive.
    ///
    /// See [StyxHook::code()] for information on code hooks.
    fn code_hook(
        &mut self,
        start: u64,
        end: u64,
        hook: Box<dyn CodeHook + 'static>,
    ) -> Result<HookToken, AddHookError> {
        self.add_hook(StyxHook::Code((start..=end).into(), hook))
    }

    /// Add a memory protection fault hook between addresses `start` and `end` inclusive.
    ///
    /// See [StyxHook::protection_fault()] for information on memory protection fault hooks.
    fn protection_fault_hook(
        &mut self,
        start: u64,
        end: u64,
        hook: Box<dyn ProtectionFaultHook + 'static>,
    ) -> Result<HookToken, AddHookError> {
        self.add_hook(StyxHook::ProtectionFault((start..=end).into(), hook))
    }

    /// Add a unmapped memory fault hook between addresses `start` and `end` inclusive.
    ///
    /// See [StyxHook::unmapped_fault()] for information on protection memory fault hooks.
    fn unmapped_fault_hook(
        &mut self,
        start: u64,
        end: u64,
        hook: Box<dyn UnmappedFaultHook + 'static>,
    ) -> Result<HookToken, AddHookError> {
        self.add_hook(StyxHook::UnmappedFault((start..=end).into(), hook))
    }

    /// Add a memory read hook between addresses `start` and `end` inclusive.
    ///
    /// See [StyxHook::memory_read()] for information on memory read hooks.
    fn mem_read_hook(
        &mut self,
        start: u64,
        end: u64,
        hook: Box<dyn MemoryReadHook + 'static>,
    ) -> Result<HookToken, AddHookError> {
        self.add_hook(StyxHook::MemoryRead((start..=end).into(), hook))
    }

    /// Add a memory read hook with data between addresses `start` and `end` inclusive.
    ///
    /// See [StyxHook::memory_read()] for information on memory read hooks.
    #[deprecated(
        since = "1.0.0",
        note = "Users should instead use [StyxHook::memory_read()] with a closure and capture a value or create a struct that implements [MemoryReadHook] and owns a value."
    )]
    fn mem_read_hook_data(
        &mut self,
        start: u64,
        end: u64,
        hook: MemoryReadHookDataFn,
        data: HookUserData,
    ) -> Result<HookToken, AddHookError> {
        self.add_hook(StyxHook::MemoryRead(
            (start..=end).into(),
            Box::new(MemoryReadHookData {
                callback: hook,
                data,
            }),
        ))
    }

    /// Add a memory write hook with data between addresses `start` and `end` inclusive.
    ///
    /// See [StyxHook::memory_write()] for information on memory write hooks.
    fn mem_write_hook(
        &mut self,
        start: u64,
        end: u64,
        hook: Box<dyn MemoryWriteHook + 'static>,
    ) -> Result<HookToken, AddHookError> {
        self.add_hook(StyxHook::MemoryWrite((start..=end).into(), hook))
    }

    /// Add a memory write hook with data between addresses `start` and `end` inclusive.
    ///
    /// See [StyxHook::memory_write()] for information on memory write hooks.
    #[deprecated(
        since = "1.0.0",
        note = "Users should instead use [StyxHook::memory_write()] with a closure and capture a value or create a struct that implements [MemoryWriteHook] and owns a value."
    )]
    fn mem_write_hook_data(
        &mut self,
        start: u64,
        end: u64,
        hook: MemoryWriteHookDataFn,
        data: HookUserData,
    ) -> Result<HookToken, AddHookError> {
        self.add_hook(StyxHook::MemoryWrite(
            (start..=end).into(),
            Box::new(MemoryWriteHookData {
                callback: hook,
                data,
            }),
        ))
    }

    /// Add an interrupt hook.
    ///
    /// See [StyxHook::interrupt()] for information on interrupt hooks.
    fn intr_hook(
        &mut self,
        hook: Box<dyn InterruptHook + 'static>,
    ) -> Result<HookToken, AddHookError> {
        self.add_hook(StyxHook::Interrupt(hook))
    }

    /// Add an invalid instruction hook.
    ///
    /// See [StyxHook::invalid_instruction()] for information on invalid instruction hooks.
    fn invalid_intr_hook(
        &mut self,
        hook: Box<dyn InvalidInstructionHook + 'static>,
    ) -> Result<HookToken, AddHookError> {
        self.add_hook(StyxHook::InvalidInstruction(hook))
    }
}

#[cfg(test)]
mod tests {
    use crate::hooks::CoreHandle;

    use super::*;

    struct TestHookable;
    impl Hookable for TestHookable {
        fn add_hook(&mut self, _hook: StyxHook) -> Result<HookToken, AddHookError> {
            Ok(HookToken::new_integer(0))
        }

        fn delete_hook(&mut self, _token: HookToken) -> Result<(), DeleteHookError> {
            Ok(())
        }
    }

    #[test]
    fn test_code_hook_helper_function() {
        let code_hook = |_proc: CoreHandle| Ok(());

        let mut hookable = TestHookable;
        let start = 0x100;
        let end = 0x110;

        hookable
            .add_hook(StyxHook::code(start..end, code_hook))
            .unwrap();

        hookable.code_hook(start, end, Box::new(code_hook)).unwrap();
    }

    #[test]
    fn test_mutable_data_custom_struct() {
        #[derive(Default)]
        struct MyCustomCodeHook {
            x: u32,
            y: String,
        }
        impl CodeHook for MyCustomCodeHook {
            fn call(&mut self, _cpu: CoreHandle) -> Result<(), UnknownError> {
                self.x += 1;
                self.y = format!("data: {}", self.x);
                println!("{}", self.y);
                Ok(())
            }
        }

        let mut hookable = TestHookable;
        let start = 0x100;
        let end = 0x110;

        hookable
            .add_hook(StyxHook::code(start..end, MyCustomCodeHook::default()))
            .unwrap();
    }

    fn my_code_hook(_proc: CoreHandle) -> Result<(), UnknownError> {
        Ok(())
    }

    #[test]
    fn test_code_hook_with_function() {
        let mut hookable = TestHookable;
        let start = 0x100;
        let end = 0x110;

        hookable
            .add_hook(StyxHook::code(start..end, my_code_hook))
            .unwrap();

        hookable
            .code_hook(start, end, Box::new(my_code_hook))
            .unwrap();
    }
}
