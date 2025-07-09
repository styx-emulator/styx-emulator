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

//! Hook subsystem of the pcode emulation machine.
//!
//! The hook subsystem handles the implementation details of storing and dispatching hooks by
//! interfacing with the [HookManager].
//!
//! ## Internals
//!
//! Hooks are represented by types (e.g. [MemoryReadHook], [InterruptHook], etc.).
//!
//! The [HookManager] contains several "buckets", one for each hook type. Each hook bucket can be
//! put into one of two categories, unconditional trigger or address range trigger whose logic is
//! contained in [HookBucket] and [AddrHookBucket] respectively.
//!
//! Hooks that are executed on every trigger (e.g. [InterruptHook]) should use the
//! [HookBucket] while hooks that only execute if the address is in their range go in
//! the [AddrHookBucket].
//!
//! Both buckets are generic over the underlying hook so the [HookManager] has several instances of each
//! bucket, each generic for a different hook.
//!
//! The [HookManager] defines separate function for each hook type which generically dispatches to
//! its correct bucket.
//!
mod buckets;

use buckets::address::AddrHookBucket;
use buckets::any::HookBucket;
use buckets::register::RegisterHookBucket;
use styx_cpu_type::arch::backends::ArchRegister;
use styx_cpu_type::arch::RegisterValue;

use crate::{PcodeBackend, PcodeBackendConfiguration};
use derivative::Derivative;
use log::trace;
use styx_errors::anyhow::{anyhow, Context};
use styx_errors::{ErrorBuffer, UnknownError};
use styx_processor::event_controller::ExceptionNumber;
use styx_processor::hooks::{
    BlockHook, DeleteHookError, HookToken, InterruptHook, InvalidInstructionHook, MemFaultData,
    MemoryReadHook, MemoryWriteHook, ProtectionFaultHook, RegisterReadHook, RegisterWriteHook,
    Resolution, UnmappedFaultHook,
};
use styx_processor::memory::MemoryPermissions;
use styx_processor::{
    cpu::CpuBackend,
    event_controller::EventController,
    hooks::{AddHookError, CodeHook, CoreHandle, Hookable, StyxHook},
    memory::Mmu,
};

/// Main manager for hooks in pcode emulation machine.
#[derive(Derivative)]
#[derivative(Debug, Default)]
pub struct HookManager {
    /// Current token value, incremented for each token to ensure all tokens are unique.
    current_token: u64,

    // All hook containers
    code_hooks: OptionalHookBucket<AddrHookBucket<Box<dyn CodeHook>>>,
    memory_read_hooks: OptionalHookBucket<AddrHookBucket<Box<dyn MemoryReadHook>>>,
    memory_write_hooks: OptionalHookBucket<AddrHookBucket<Box<dyn MemoryWriteHook>>>,
    interrupt_hooks: OptionalHookBucket<HookBucket<Box<dyn InterruptHook>>>,
    block_hooks: OptionalHookBucket<HookBucket<Box<dyn BlockHook>>>,
    invalid_instruction_hooks: OptionalHookBucket<HookBucket<Box<dyn InvalidInstructionHook>>>,
    protection_fault_hooks: OptionalHookBucket<AddrHookBucket<Box<dyn ProtectionFaultHook>>>,
    unmapped_fault_hooks: OptionalHookBucket<AddrHookBucket<Box<dyn UnmappedFaultHook>>>,
    register_read_hooks: OptionalHookBucket<RegisterHookBucket<Box<dyn RegisterReadHook>>>,
    register_write_hooks: OptionalHookBucket<RegisterHookBucket<Box<dyn RegisterWriteHook>>>,
}

/// Used to mock the main backend struct in testing.
pub trait HasHookManager {
    fn hook_manager(&mut self) -> &mut HookManager;
}
impl HasHookManager for PcodeBackend {
    fn hook_manager(&mut self) -> &mut HookManager {
        &mut self.hook_manager
    }
}

impl Hookable for PcodeBackend {
    fn add_hook(&mut self, hook: StyxHook) -> Result<HookToken, AddHookError> {
        self.hook_manager.add_hook(&self.pcode_config, hook)
    }

    fn delete_hook(&mut self, token: HookToken) -> Result<(), DeleteHookError> {
        self.hook_manager().delete_hook(token)
    }
}

/// Hook bucket for hooks that are always activated, no matter the trigger data.
#[derive(derive_more::Debug)]
enum OptionalHookBucket<C> {
    Available(C),
    Unavailable,
}

// Default cannot be derived for AddressableHookBucket, implement explicitly.
impl<H: Default> Default for OptionalHookBucket<H> {
    fn default() -> Self {
        Self::Available(Default::default())
    }
}
impl<C> OptionalHookBucket<C> {
    fn available(&mut self) -> Result<&mut C, UnknownError> {
        match self {
            OptionalHookBucket::Available(hook_bucket) => Ok(hook_bucket),
            OptionalHookBucket::Unavailable => Err(anyhow!("hook bucket not available")),
        }
    }

    fn take(&mut self) -> Result<C, UnknownError> {
        let old_bucket = std::mem::replace(self, OptionalHookBucket::Unavailable);
        match old_bucket {
            OptionalHookBucket::Available(hook_bucket) => Ok(hook_bucket),
            OptionalHookBucket::Unavailable => Err(anyhow!("hook bucket not available")),
        }
    }

    fn put_back(&mut self, bucket: C) {
        *self = OptionalHookBucket::Available(bucket);
    }
}

impl HookManager {
    /// Create a new [HookManager] and supply a `backend` that will be passed to callbacks.
    pub fn new() -> Self {
        Self {
            current_token: 0,
            // Empty hooks
            ..Default::default()
        }
    }

    /// Gets a unique token by incrementing a counter every query.
    fn get_unique_token(&mut self) -> HookToken {
        let token = HookToken::new_integer(self.current_token);
        self.current_token = self
            .current_token
            .checked_add(1)
            .expect("current token overflowed, cannot guarantee unique tokens");
        token
    }

    pub fn add_hook(
        &mut self,
        config: &PcodeBackendConfiguration,
        hook: StyxHook,
    ) -> Result<HookToken, AddHookError> {
        let token = self.get_unique_token();
        trace!("adding hook: {hook:?}[{token:?}]",);

        match hook {
            StyxHook::Code(range, hook) => {
                self.code_hooks.available()?.add_hook(token, range, hook);
            }
            StyxHook::MemoryRead(range, hook) => {
                self.memory_read_hooks
                    .available()?
                    .add_hook(token, range, hook);
            }
            StyxHook::MemoryWrite(range, hook) => {
                self.memory_write_hooks
                    .available()?
                    .add_hook(token, range, hook);
            }
            StyxHook::Interrupt(hook) => {
                self.interrupt_hooks.available()?.add_hook(token, hook);
            }
            StyxHook::InvalidInstruction(hook) => {
                self.invalid_instruction_hooks
                    .available()?
                    .add_hook(token, hook);
            }
            StyxHook::ProtectionFault(range, hook) => {
                self.protection_fault_hooks
                    .available()?
                    .add_hook(token, range, hook);
            }
            StyxHook::UnmappedFault(range, hook) => {
                self.unmapped_fault_hooks
                    .available()?
                    .add_hook(token, range, hook);
            }
            StyxHook::Block(hook) => {
                self.block_hooks.available()?.add_hook(token, hook);
            }
            StyxHook::RegisterRead(register, hook) => {
                if config.register_read_hooks {
                    self.register_read_hooks
                        .available()?
                        .add_hook(token, register, hook);
                } else {
                    return Err(AddHookError::HookTypeNotSupported);
                }
            }
            StyxHook::RegisterWrite(register, hook) => {
                if config.register_write_hooks {
                    self.register_write_hooks
                        .available()?
                        .add_hook(token, register, hook);
                } else {
                    return Err(AddHookError::HookTypeNotSupported);
                }
            }
            _ => return Err(AddHookError::HookTypeNotSupported),
        }

        Ok(token)
    }

    /// Delete a hook from the manager. Errors if the `token` is not found.
    pub fn delete_hook(&mut self, token: HookToken) -> Result<(), DeleteHookError> {
        // Tries each hook bank and returns Ok if one of them successfully deleted, otherwise gives
        // a `StyxHookError::HookRemoveError`.
        // Assumes that all hook tokens are unique.
        None.or(self
            .code_hooks
            .available()
            .ok()
            .and_then(|a| a.delete_hook(token)))
            .or(self
                .memory_read_hooks
                .available()
                .ok()
                .and_then(|a| a.delete_hook(token)))
            .or(self
                .memory_write_hooks
                .available()
                .ok()
                .and_then(|a| a.delete_hook(token)))
            .or(self
                .interrupt_hooks
                .available()
                .ok()
                .and_then(|a| a.delete_hook(token)))
            .or(self
                .block_hooks
                .available()
                .ok()
                .and_then(|a| a.delete_hook(token)))
            .or(self
                .invalid_instruction_hooks
                .available()
                .ok()
                .and_then(|a| a.delete_hook(token)))
            .or(self
                .protection_fault_hooks
                .available()
                .ok()
                .and_then(|a| a.delete_hook(token)))
            .or(self
                .unmapped_fault_hooks
                .available()
                .ok()
                .and_then(|a| a.delete_hook(token)))
            .or(self
                .register_read_hooks
                .available()
                .ok()
                .and_then(|a| a.delete_hook(token)))
            .or(self
                .register_write_hooks
                .available()
                .ok()
                .and_then(|a| a.delete_hook(token)))
            .ok_or(DeleteHookError::HookDoesNotExist)
    }

    pub fn trigger_code_hook<T: HasHookManager + CpuBackend>(
        cpu: &mut T,
        mmu: &mut Mmu,
        ev: &mut EventController,
        addr: u64,
    ) -> Result<(), UnknownError> {
        let mut hook_bucket = cpu.hook_manager().code_hooks.take()?;

        trace!("Triggering code hook on 0x{addr:X}.");
        let mut errors = ErrorBuffer::new();
        for hook in hook_bucket.activate(addr) {
            let core_handler = CoreHandle::new(cpu, mmu, ev);
            let hook_callback_res = hook.callback.call(core_handler);
            if let Err(err) = hook_callback_res {
                errors.push(err);
            }
        }

        // replace hook bucket structure
        cpu.hook_manager().code_hooks.put_back(hook_bucket);

        errors
            .result()
            .with_context(|| "error(s) from code hook triggerings")
    }

    pub fn trigger_memory_read_hook<T: HasHookManager + CpuBackend>(
        cpu: &mut T,
        mmu: &mut Mmu,
        ev: &mut EventController,
        addr: u64,
        size: u32,
        data: &mut [u8],
    ) -> Result<(), UnknownError> {
        let mut hook_bucket = cpu.hook_manager().memory_read_hooks.take()?;

        trace!("Triggering memory read hooks on 0x{addr:X}.");
        let mut errors = ErrorBuffer::new();
        for hook in hook_bucket.activate(addr) {
            trace!("exec token {:?}.", hook.token);
            let core_handler = CoreHandle::new(cpu, mmu, ev);
            let hook_callback_res = hook.callback.call(core_handler, addr, size, data);
            if let Err(err) = hook_callback_res {
                errors.push(err);
            }
        }

        // replace hook bucket structure
        cpu.hook_manager().memory_read_hooks.put_back(hook_bucket);

        errors
            .result()
            .with_context(|| "error(s) from memory read hook triggerings")
    }

    pub fn trigger_memory_write_hook<T: HasHookManager + CpuBackend>(
        cpu: &mut T,
        mmu: &mut Mmu,
        ev: &mut EventController,
        addr: u64,
        size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        let mut hook_bucket = cpu.hook_manager().memory_write_hooks.take()?;

        trace!("Triggering memory write hooks on 0x{addr:X}.");
        let mut errors = ErrorBuffer::new();
        for hook in hook_bucket.activate(addr) {
            trace!("exec token {:?}.", hook.token);
            let core_handler = CoreHandle::new(cpu, mmu, ev);
            let hook_callback_res = hook.callback.call(core_handler, addr, size, data);
            if let Err(err) = hook_callback_res {
                errors.push(err);
            }
        }

        // replace hook bucket structure
        cpu.hook_manager().memory_write_hooks.put_back(hook_bucket);

        errors
            .result()
            .with_context(|| "error(s) from memory write hook triggerings")
    }

    pub fn trigger_invalid_instruction_hook<T: HasHookManager + CpuBackend>(
        cpu: &mut T,
        mmu: &mut Mmu,
        ev: &mut EventController,
    ) -> Result<Resolution, UnknownError> {
        let mut hook_bucket = cpu.hook_manager().invalid_instruction_hooks.take()?;

        trace!("Triggering invalid instruction hook.");
        let mut errors = ErrorBuffer::new();
        let mut fixed = Resolution::default();
        for hook in hook_bucket.activate() {
            let core_handler = CoreHandle::new(cpu, mmu, ev);
            let hook_callback_res = hook.callback.call(core_handler);
            match hook_callback_res {
                Ok(is_now_fixed) => fixed = fixed & is_now_fixed,
                Err(err) => errors.push(err),
            }
        }

        // replace hook bucket structure
        cpu.hook_manager()
            .invalid_instruction_hooks
            .put_back(hook_bucket);

        errors
            .result()
            .with_context(|| "error(s) from invalid instruction hook triggerings")
            .map(|_| fixed)
    }

    pub fn trigger_interrupt_hook<T: HasHookManager + CpuBackend>(
        cpu: &mut T,
        mmu: &mut Mmu,
        ev: &mut EventController,
        irqn: ExceptionNumber,
    ) -> Result<(), UnknownError> {
        let mut hook_bucket = cpu.hook_manager().interrupt_hooks.take()?;

        trace!("Triggering interrupt hook {irqn}");
        let mut errors = ErrorBuffer::new();
        for hook in hook_bucket.activate() {
            let core_handler = CoreHandle::new(cpu, mmu, ev);
            let hook_callback_res = hook.callback.call(core_handler, irqn);
            match hook_callback_res {
                Ok(_) => (),
                Err(err) => errors.push(err),
            }
        }

        // replace hook bucket structure
        cpu.hook_manager().interrupt_hooks.put_back(hook_bucket);

        errors
            .result()
            .with_context(|| "error(s) from interrupt hook triggerings")
    }

    pub fn trigger_protection_fault_hook<T: HasHookManager + CpuBackend>(
        cpu: &mut T,
        mmu: &mut Mmu,
        ev: &mut EventController,
        addr: u64,
        size: u32,
        permission: MemoryPermissions,
        fault_data: MemFaultData,
    ) -> Result<Resolution, UnknownError> {
        let mut hook_bucket = cpu.hook_manager().protection_fault_hooks.take()?;

        trace!("Triggering protection fault hooks on 0x{addr:X}.");
        let mut errors = ErrorBuffer::new();
        let mut fixed = Resolution::default();
        for hook in hook_bucket.activate(addr) {
            trace!("exec token {:?}.", hook.token);
            let core_handler = CoreHandle::new(cpu, mmu, ev);
            let hook_callback_res =
                hook.callback
                    .call(core_handler, addr, size, permission, fault_data);
            match hook_callback_res {
                Ok(is_now_fixed) => fixed = fixed & is_now_fixed,
                Err(err) => errors.push(err),
            }
        }

        // replace hook bucket structure
        cpu.hook_manager()
            .protection_fault_hooks
            .put_back(hook_bucket);

        errors
            .result()
            .with_context(|| "error(s) from protection fault triggerings")
            .map(|_| fixed)
    }

    pub fn trigger_unmapped_fault_hook<T: HasHookManager + CpuBackend>(
        cpu: &mut T,
        mmu: &mut Mmu,
        ev: &mut EventController,
        addr: u64,
        size: u32,
        fault_data: MemFaultData,
    ) -> Result<Resolution, UnknownError> {
        let mut hook_bucket = cpu.hook_manager().unmapped_fault_hooks.take()?;

        trace!("Triggering unmapped fault hooks on 0x{addr:X}.");
        let mut errors = ErrorBuffer::new();
        let mut fixed = Resolution::default();
        for hook in hook_bucket.activate(addr) {
            trace!("exec token {:?}.", hook.token);
            let core_handler = CoreHandle::new(cpu, mmu, ev);
            let hook_callback_res = hook.callback.call(core_handler, addr, size, fault_data);
            match hook_callback_res {
                Ok(is_now_fixed) => fixed = fixed & is_now_fixed,
                Err(err) => errors.push(err),
            }
        }

        // replace hook bucket structure
        cpu.hook_manager()
            .unmapped_fault_hooks
            .put_back(hook_bucket);

        errors
            .result()
            .with_context(|| "error(s) from unmapped fault triggerings")
            .map(|_| fixed)
    }

    pub(crate) fn trigger_block_hook<T: HasHookManager + CpuBackend>(
        cpu: &mut T,
        mmu: &mut Mmu,
        ev: &mut EventController,
        addr: u64,
        size: u32,
    ) -> Result<(), UnknownError> {
        let mut hook_bucket = cpu.hook_manager().block_hooks.take()?;

        trace!("Triggering block hook on 0x{addr:X}.");
        let mut errors = ErrorBuffer::new();
        for hook in hook_bucket.activate() {
            let core_handler = CoreHandle::new(cpu, mmu, ev);
            let hook_callback_res = hook.callback.call(core_handler, addr, size);
            if let Err(err) = hook_callback_res {
                errors.push(err);
            }
        }

        // replace hook bucket structure
        cpu.hook_manager().block_hooks.put_back(hook_bucket);

        errors
            .result()
            .with_context(|| "error(s) from block hook triggerings")
    }

    pub(crate) fn block_hook_count(&mut self) -> Result<usize, UnknownError> {
        Ok(self.block_hooks.available()?.num_hooks())
    }

    pub fn trigger_register_read_hook<T: HasHookManager + CpuBackend>(
        cpu: &mut T,
        mmu: &mut Mmu,
        ev: &mut EventController,
        register: ArchRegister,
        data: &mut RegisterValue,
    ) -> Result<(), UnknownError> {
        let mut hook_bucket = cpu.hook_manager().register_read_hooks.take()?;

        trace!("Triggering register read hook for {register}.");
        let mut errors = ErrorBuffer::new();
        for hook in hook_bucket.activate(register) {
            let core_handler = CoreHandle::new(cpu, mmu, ev);
            let hook_callback_res = hook.callback.call(core_handler, register, data);
            if let Err(err) = hook_callback_res {
                errors.push(err);
            }
        }

        // replace hook bucket structure
        cpu.hook_manager().register_read_hooks.put_back(hook_bucket);

        errors
            .result()
            .with_context(|| "error(s) from register read hook triggerings")
    }

    pub fn trigger_register_write_hook<T: HasHookManager + CpuBackend>(
        cpu: &mut T,
        mmu: &mut Mmu,
        ev: &mut EventController,
        register: ArchRegister,
        data: &RegisterValue,
    ) -> Result<(), UnknownError> {
        let mut hook_bucket = cpu.hook_manager().register_write_hooks.take()?;

        trace!("Triggering register write for {register}.");
        let mut errors = ErrorBuffer::new();
        for hook in hook_bucket.activate(register) {
            let core_handler = CoreHandle::new(cpu, mmu, ev);
            let hook_callback_res = hook.callback.call(core_handler, register, data);
            if let Err(err) = hook_callback_res {
                errors.push(err);
            }
        }

        // replace hook bucket structure
        cpu.hook_manager()
            .register_write_hooks
            .put_back(hook_bucket);

        errors
            .result()
            .with_context(|| "error(s) from register write hook triggerings")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    use styx_processor::{
        core::ProcessorCore,
        cpu::{CpuBackend, ExecutionReport},
    };

    use super::*;

    #[test]
    fn test_address_hook_single() {
        let mut captain = AddrHookBucket::<Box<dyn CodeHook>>::default();

        let token = HookToken::new_integer(0x1337);
        let read_memory_callback = move |_: CoreHandle| Ok(());

        captain.add_hook(
            token,
            (0x1000..0x1100).into(),
            Box::new(read_memory_callback),
        );

        let none = captain.activate(0x500);
        assert_eq!(none.count(), 0);

        let some = captain.activate(0x1050);
        assert_eq!(some.count(), 1);
    }

    #[derive(Debug, Default)]
    struct DummyPcodeBackend {
        hook_manager: HookManager,
    }
    impl HasHookManager for DummyPcodeBackend {
        fn hook_manager(&mut self) -> &mut HookManager {
            &mut self.hook_manager
        }
    }
    impl Hookable for DummyPcodeBackend {
        fn add_hook(&mut self, hook: StyxHook) -> Result<HookToken, AddHookError> {
            self.hook_manager()
                .add_hook(&PcodeBackendConfiguration::default(), hook)
        }

        fn delete_hook(&mut self, token: HookToken) -> Result<(), DeleteHookError> {
            self.hook_manager().delete_hook(token)
        }
    }
    impl CpuBackend for DummyPcodeBackend {
        fn read_register_raw(
            &mut self,
            _reg: styx_cpu_type::arch::backends::ArchRegister,
        ) -> Result<styx_cpu_type::arch::RegisterValue, styx_processor::cpu::ReadRegisterError>
        {
            todo!()
        }

        fn write_register_raw(
            &mut self,
            _reg: styx_cpu_type::arch::backends::ArchRegister,
            _value: styx_cpu_type::arch::RegisterValue,
        ) -> Result<(), styx_processor::cpu::WriteRegisterError> {
            todo!()
        }

        fn architecture(&self) -> &dyn styx_cpu_type::arch::ArchitectureDef {
            todo!()
        }

        fn endian(&self) -> styx_cpu_type::ArchEndian {
            todo!()
        }

        fn execute(
            &mut self,
            _mmu: &mut Mmu,
            _event_controller: &mut EventController,
            _count: u64,
        ) -> Result<ExecutionReport, styx_errors::UnknownError> {
            todo!()
        }

        fn pc(&mut self) -> Result<u64, styx_errors::UnknownError> {
            todo!()
        }

        fn set_pc(&mut self, _value: u64) -> Result<(), styx_errors::UnknownError> {
            todo!()
        }

        fn stop(&mut self) {
            todo!()
        }

        fn context_save(&mut self) -> Result<(), UnknownError> {
            todo!()
        }

        fn context_restore(&mut self) -> Result<(), UnknownError> {
            todo!()
        }
    }
    #[test]
    fn test_address_hook_singled() {
        let captain = HookManager::default();
        let mut cpu = DummyPcodeBackend {
            hook_manager: captain,
        };
        let is_triggered = Arc::new(AtomicBool::new(false));
        let code_hook = {
            let is_triggered = is_triggered.clone();
            move |_: CoreHandle| {
                is_triggered.store(true, Ordering::SeqCst);
                Ok(())
            }
        };
        cpu.hook_manager()
            .add_hook(
                &PcodeBackendConfiguration::default(),
                StyxHook::code(0x1000..0x1100, code_hook),
            )
            .unwrap();

        // generate a dummy mmu and event_controller
        let mut core = ProcessorCore::dummy();

        // outside of range, shouldn't trigger yet
        HookManager::trigger_code_hook(&mut cpu, &mut core.mmu, &mut core.event_controller, 0x100)
            .unwrap();
        assert!(!is_triggered.load(Ordering::SeqCst));

        // inside of range, triggered
        HookManager::trigger_code_hook(&mut cpu, &mut core.mmu, &mut core.event_controller, 0x1050)
            .unwrap();
        assert!(is_triggered.load(Ordering::SeqCst));
    }
}
