// SPDX-License-Identifier: BSD-2-Clause

//! Given a [`StyxHookDescriptor`] object and the current value of hook parameters, execute the
//! callback. this is necessary because the unicorn_engine callbacks are already in a specific
//! format, we're interjecting our own hook layer to port unicorn to our stuff.
//!
//! The spicy logic is handled in [hook_proxy()].
//!
//! In order to access the [crate::UnicornBackend], mmu, and event controller, we give each
//! [StyxHookDescriptor] a pointer to the backend's [crate::CorePointers]. These are updated every
//! time the backend is executed to ensure the pointers are valid if the user moves them.
//!
//! Errors in hooks are stored in the unicorn backend and emulation is stopped.
use log::trace;
use std::ops::RangeBounds;
use styx_errors::{anyhow::anyhow, UnknownError};
use styx_processor::{
    core::{Exception, HandleExceptionAction},
    event_controller::EventController,
    hooks::{CoreHandle, MemFaultData, Resolution, StyxHook},
    memory::{
        helpers::{ReadExt, WriteExt},
        MemoryRegionSize, Mmu,
    },
};
use unicorn_engine::unicorn_const;

use crate::{hooks::StyxHookDescriptor, UnicornBackend};

/// Extracts hook and [CoreHandle] references from ptr_state and hook pointers and gives them to a
/// hook specific logic callback `F`. The hook logic callback is in charge of calling the [StyxHook]
/// call function but can also sanity check the hook type and address args.
fn hook_proxy<T, F: FnOnce(CoreHandle, &mut StyxHook) -> Result<T, UnknownError>>(
    hook: *mut StyxHookDescriptor,
    hook_logic: F,
) -> Option<T> {
    hook_proxy_separate(hook, |cpu, mmu, ev, hook| {
        let core = CoreHandle::new(cpu, mmu, ev);
        hook_logic(core, hook)
    })
}

/// Same as [`hook_proxy`] but with the trinity split out.
fn hook_proxy_separate<
    T,
    F: FnOnce(
        &mut UnicornBackend,
        &mut Mmu,
        &mut EventController,
        &mut StyxHook,
    ) -> Result<T, UnknownError>,
>(
    hook: *mut StyxHookDescriptor,
    hook_logic: F,
) -> Option<T> {
    debug_assert!(!hook.is_null());
    // SAFETY: given by unicorn, we can assume valid
    let hook = unsafe { &mut *hook };
    // SAFETY: core pointers is pinned when adding to styx hooks. we can also assume that if the
    // unicorn instance exists then the unicorn backend still exists.
    let ptr_core = unsafe { &mut *hook.core };
    // SAFETY: these are set before starting unicorn execution but after we secure a mut ref to them
    // in the unicorn backend, ensuring they remain valid.
    let cpu = unsafe { &mut *ptr_core.unicorn_backend };
    let mmu = unsafe { &mut *ptr_core.mmu };
    let ev = unsafe { &mut *ptr_core.event_controller };

    log::trace!("hook proxy call hook {:?}", hook.styx_hook);
    let hook_logic_result = hook_logic(cpu, mmu, ev, &mut hook.styx_hook);

    // re-sync memory after hook callback
    if !cpu.check_synced(mmu).unwrap() {
        cpu.sync_regions(mmu).unwrap();
    }

    match hook_logic_result {
        Err(err) => {
            log::error!("error in hook `{err:?}`");
            cpu.hook_error(err);
            None
        }
        Ok(value) => Some(value),
    }
}

pub fn code_hook_proxy(
    _uc: unicorn_engine::ffi::uc_handle,
    address: u64,
    _size: u32,
    hook: *mut StyxHookDescriptor,
) {
    log::trace!("code hook proxy at 0x{address:X}");

    hook_proxy(hook, |proc, hook| {
        let StyxHook::Code(range, hook) = hook else {
            panic!(
                "Invalid hook type called on code_hook_proxy, got: {:?}",
                hook
            )
        };

        // check that the code hook is valid
        debug_assert!(
            range.contains(&address),
            "Trigger address: 0x{address:x} is not in hook range {range:?}",
        );

        hook.call(proc)
    });
}

pub fn mem_write_proxy(
    _uc: unicorn_engine::ffi::uc_handle,
    mem_type: unicorn_const::MemType,
    address: u64,
    size: usize,
    value: i64,
    hook: *mut StyxHookDescriptor,
) {
    log::trace!("memory write hook proxy at 0x{address:X}");

    hook_proxy(hook, |proc, hook| {
        let StyxHook::MemoryWrite(range, hook) = hook else {
            panic!(
                "Invalid hook type called on mem_write_hook_proxy, got: {:?}",
                hook
            )
        };

        debug_assert!(mem_type == unicorn_const::MemType::WRITE);
        // check that the code hook is valid
        debug_assert!(
            range.contains(&address),
            "Trigger address: 0x{address:x} is not in hook range {range:?}",
        );
        // We don't do the following assertion because in unicorn
        // the `start` and `end` addresses are both used as the
        // memory write "start" addresses to look for. the size
        // is not taken into account.
        //
        // debug_assert!(address + size as u64 <= mem_hook.end);

        // move data into a ref
        let data: &[u8] = match proc.endian() {
            styx_cpu_type::ArchEndian::LittleEndian => &value.to_le_bytes(),
            styx_cpu_type::ArchEndian::BigEndian => &value.to_be_bytes(),
        };

        hook.call(proc, address, size as u32, data)
    });
}

pub fn mem_read_proxy(
    _uc: unicorn_engine::ffi::uc_handle,
    mem_type: unicorn_const::MemType,
    address: u64,
    size: usize,
    _value: i64, // always 0
    hook: *mut StyxHookDescriptor,
) {
    log::trace!("memory write hook proxy at 0x{address:X}");

    hook_proxy(hook, |proc, hook| {
        let StyxHook::MemoryRead(range, hook) = hook else {
            panic!(
                "Invalid hook type called on mem_read_proxy, got: {:?}",
                hook
            )
        };

        debug_assert!(mem_type == unicorn_const::MemType::READ);
        // check that the code hook is valid
        debug_assert!(
            range.contains(&address),
            "Trigger address: 0x{address:x} is not in hook range {range:?}",
        );

        // Note: we use a memory read because _value will always have a value of zero in a memory read hook
        // Source:
        // https://github.com/unicorn-engine/unicorn/blob/d4b92485b1a228fb003e1218e42f6c778c655809/qemu/accel/tcg/cputlb.c#L1513

        let mut buf = vec![0; size].into_boxed_slice();

        match proc.mmu.data().read(address).bytes(&mut buf) {
            Ok(_) => {
                let original_data = buf.clone();

                // deconstruct our core handle
                let CoreHandle {
                    cpu,
                    mmu,
                    event_controller,
                } = proc;

                // core handle for the hook callback
                let hook_proc = CoreHandle {
                    cpu,
                    mmu,
                    event_controller,
                };
                let res = hook.call(hook_proc, address, size as u32, &mut buf);

                // write new data to memory if changed
                if buf != original_data {
                    // core handle to write the modified memory back
                    let rewrite_proc = CoreHandle {
                        cpu,
                        mmu,
                        event_controller,
                    };
                    // unwrap should be safe here, we are writing to the same spot we read from earlier
                    rewrite_proc.mmu.data().write(address).bytes(&buf).unwrap();
                }
                res
            }
            Err(e) => Err(e.into()),
        }
    });
}

pub fn block_hook_proxy(
    _uc: unicorn_engine::ffi::uc_handle,
    address: u64,
    size: u32,
    hook: *mut StyxHookDescriptor,
) {
    hook_proxy(hook, |proc, hook| {
        let StyxHook::Block(hook) = hook else {
            panic!(
                "Invalid hook type called on block_hook_proxy, got: {:?}",
                hook
            )
        };

        // call callback + propagate the return code
        hook.call(proc, address, size)
    });
}

pub fn intr_hook_proxy(
    _uc: unicorn_engine::ffi::uc_handle,
    intno: i32,
    hook: *mut StyxHookDescriptor,
) {
    hook_proxy(hook, |proc, hook| {
        let StyxHook::Interrupt(hook) = hook else {
            panic!(
                "Invalid hook type called on intr_hook_proxy, got: {:?}",
                hook
            )
        };

        hook.call(proc, intno)
    });
}

pub fn invalid_insn_hook_proxy(
    _uc: unicorn_engine::ffi::uc_handle,
    hook: *mut StyxHookDescriptor,
) -> bool {
    trace!("invalid insn fault");
    let res = hook_proxy_separate(hook, |cpu, mmu, ev, hook| {
        let action = cpu
            .exception
            .handle_exception(Exception::InvalidInstruction);
        match action {
            HandleExceptionAction::Pause(target_exit_reason) => {
                cpu.exception_requested_stop = Some(target_exit_reason);
                Ok(Resolution::NotFixed)
            }
            // `HandleExceptionBehavior` exit reason not used here, relying on translation in
            // `execute`.
            HandleExceptionAction::TargetHandle(_) => {
                let StyxHook::InvalidInstruction(hook) = hook else {
                    panic!(
                        "Invalid hook type called on invalid_insn_proxy, got: {:?}",
                        hook
                    )
                };

                // call callback + propagate the return code
                let proc = CoreHandle::new(cpu, mmu, ev);
                hook.call(proc)
            }
        }
    });

    // deem not fixed if error
    res.unwrap_or(Resolution::NotFixed).fixed()
}

/// Used in `protection_fault_hook_proxy` to ensure that the received
/// hook type is correct
const PROT_MEM_TYPE: [unicorn_const::MemType; 3] = [
    unicorn_const::MemType::READ_PROT,
    unicorn_const::MemType::WRITE_PROT,
    unicorn_const::MemType::FETCH_PROT,
];

pub fn protection_fault_hook_proxy(
    _uc: unicorn_engine::ffi::uc_handle,
    mem_type: unicorn_const::MemType,
    address: u64,
    size: usize,
    value: i64, // always 0 when `mem_type` is a `READ_PROT`
    hook: *mut StyxHookDescriptor,
) -> bool {
    let res = hook_proxy_separate(hook, |cpu, mmu, ev, hook| {
        let exception = match mem_type {
            unicorn_const::MemType::READ_PROT => Exception::UnmappedMemoryRead,
            unicorn_const::MemType::WRITE_PROT => Exception::UnmappedMemoryWrite,
            unicorn_const::MemType::FETCH_PROT => Exception::UnmappedMemoryFetch,
            _ => return Err(anyhow!("unexpected mem_type {mem_type:?}")),
        };
        let exception_behavior = cpu.exception;
        let action = exception_behavior.handle_exception(exception);

        match action {
            HandleExceptionAction::Pause(target_exit_reason) => {
                cpu.exception_requested_stop = Some(target_exit_reason);
                Ok(Resolution::NotFixed)
            }
            // `HandleExceptionBehavior` exit reason not used here, relying on translation in
            // `execute`.
            HandleExceptionAction::TargetHandle(_) => {
                let StyxHook::ProtectionFault(range, hook) = hook else {
                    panic!(
                        "Invalid hook type called on protection_fault_hook_proxy, got: {:?}",
                        hook
                    )
                };

                // validate
                debug_assert!(
                    PROT_MEM_TYPE.contains(&mem_type),
                    "Invalid MemType provided to protection_fault_hook_proxy"
                );
                debug_assert!(
                    range.contains(&address),
                    "Trigger address: 0x{address:X} is not in {range:?}",
                );
                let proc = CoreHandle::new(cpu, mmu, ev);
                // get the fault data for the callback
                let fault_bytes = match proc.endian() {
                    styx_cpu_type::ArchEndian::LittleEndian => value.to_le_bytes(),
                    styx_cpu_type::ArchEndian::BigEndian => value.to_be_bytes(),
                };
                let fault_data = match mem_type {
                    unicorn_const::MemType::WRITE_UNMAPPED => {
                        MemFaultData::Write { data: &fault_bytes }
                    }
                    // we map both the fetch and the read variant into `READ`
                    _ => MemFaultData::Read,
                };
                // get the permissions of the underlying memory region
                let perms = proc
                    .mmu
                    .regions()
                    .expect("mmu for unicorn engine MUST have regions")
                    .find(|region| region.contains_region((address, size as u64)))
                    .map(|r| r.perms)
                    .expect("unicorn protection fault in nonexistent region?");

                hook.call(proc, address, size as u32, perms, fault_data)
            }
        }
    });

    // deem not fixed if error
    res.unwrap_or(Resolution::NotFixed).fixed()
}

/// Used in `unmapped_fault_hook_proxy` to ensure that the received
/// hook type is correct
const UNMAPPED_MEM_TYPE: [unicorn_const::MemType; 3] = [
    unicorn_const::MemType::READ_UNMAPPED,
    unicorn_const::MemType::WRITE_UNMAPPED,
    unicorn_const::MemType::FETCH_UNMAPPED,
];

pub fn unmapped_fault_hook_proxy(
    _uc: unicorn_engine::ffi::uc_handle,
    mem_type: unicorn_const::MemType,
    address: u64,
    size: usize,
    value: i64, // always 0 when `mem_type` is a `READ_UNMAPPED`
    hook: *mut StyxHookDescriptor,
) -> bool {
    let res = hook_proxy_separate(hook, |cpu, mmu, ev, hook| {
        let exception = match mem_type {
            unicorn_const::MemType::READ_UNMAPPED => Exception::UnmappedMemoryRead,
            unicorn_const::MemType::WRITE_UNMAPPED => Exception::UnmappedMemoryWrite,
            unicorn_const::MemType::FETCH_UNMAPPED => Exception::UnmappedMemoryFetch,
            _ => return Err(anyhow!("unexpected mem_type {mem_type:?}")),
        };
        let exception_behavior = cpu.exception;
        let action = exception_behavior.handle_exception(exception);
        match action {
            HandleExceptionAction::Pause(target_exit_reason) => {
                cpu.exception_requested_stop = Some(target_exit_reason);
                Ok(Resolution::NotFixed)
            }
            // `HandleExceptionBehavior` exit reason not used here, relying on translation in
            // `execute`.
            HandleExceptionAction::TargetHandle(_) => {
                let StyxHook::UnmappedFault(range, hook) = hook else {
                    panic!(
                        "Invalid hook type called on unmapped_fault_hook_proxy, got: {:?}",
                        hook
                    )
                };

                // validate
                debug_assert!(
                    UNMAPPED_MEM_TYPE.contains(&mem_type),
                    "Invalid MemType provided to unmapped_fault_hook_proxy"
                );
                debug_assert!(
                    range.contains(&address),
                    "Trigger address: 0x{address:X} is not in {range:?}",
                );
                let proc = CoreHandle::new(cpu, mmu, ev);
                // get the fault data for the callback
                let fault_bytes = match proc.endian() {
                    styx_cpu_type::ArchEndian::LittleEndian => value.to_le_bytes(),
                    styx_cpu_type::ArchEndian::BigEndian => value.to_be_bytes(),
                };
                let fault_data = match mem_type {
                    unicorn_const::MemType::WRITE_UNMAPPED => {
                        MemFaultData::Write { data: &fault_bytes }
                    }
                    // we map both the fetch and the read variant into `READ`
                    _ => MemFaultData::Read,
                };

                hook.call(proc, address, size as u32, fault_data)
            }
        }
    });

    // deem not fixed if error
    res.unwrap_or(Resolution::NotFixed).fixed()
}
