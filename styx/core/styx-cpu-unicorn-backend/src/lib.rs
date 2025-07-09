// SPDX-License-Identifier: BSD-2-Clause

use std::{collections::BTreeMap, ffi::c_void, marker::PhantomPinned, mem::size_of, pin::Pin};

use arbitrary_int::{u20, u40, u80};
use beau_collector::BeauCollector;
use derivative::Derivative;
use hooks::{StyxHookDescriptor, StyxHookMap};
use log::{debug, trace, warn};
use ref_cast::RefCast;
use tap::Pipe;

use unicorn_engine::{ffi, unicorn_const, HookType, MemRegion, Unicorn};

use styx_cpu_type::{
    arch::{
        arm::{SpecialArmRegister, SpecialArmRegisterValues},
        backends::{ArchRegister, ArchVariant, SpecialArchRegister},
        Arch, ArchEndian, ArchitectureDef, RegisterValue,
    },
    TargetExitReason,
};
use styx_errors::{
    anyhow::{anyhow, Context},
    UnknownError,
};
use styx_processor::{
    core::ExceptionBehavior,
    cpu::{CpuBackend, ExecutionReport, ReadRegisterError, WriteRegisterError},
    event_controller::EventController,
    hooks::{AddHookError, AddressRange, DeleteHookError, HookToken, Hookable, StyxHook},
    memory::{memory_region::MemoryRegion, MemoryPermissions, MemoryRegionSize, Mmu},
};
use styx_sync::cell::UnsafeCell;
use styx_util::unsafe_lib::{any_as_u8_slice, any_as_u8_slice_mut};

// local compatibility layers with styx + unicorn
mod arch_compat;
mod error;
mod hook_compat;
mod hooks;
mod register_compat;

use arch_compat::styx_to_unicorn_machine;
use error::UcErr;
use register_compat::{styx_to_unicorn_register, UcArmCoprocessorRegisterAction};

/// A pretty unsafe struct that is used to proxy calls to unicorn
/// while remaining [`Send`] + [`Sync`].
#[derive(Debug)]
struct UnicornHandle {
    handle: UnsafeCell<unicorn_engine::Unicorn<'static, ()>>,
}

impl UnicornHandle {
    fn new(uc: Unicorn<'static, ()>) -> Self {
        Self {
            handle: UnsafeCell::new(uc),
        }
    }

    /// This method allows us to have a rust callback system
    /// that gets invoked by a C-runtime. Using an [`UnsafeCell`]
    /// we hold a reference to our inner rust struct that invokes
    /// the unicorn api to drive the C-runtime.
    ///
    /// # Safety
    /// This is used to modify the internal struct. This should
    /// be used only to start, stop, and modify the unicorn state.
    /// The &mut returned from this method should never be passed
    /// around.
    ///
    /// TODO: make this method `unsafe`
    #[allow(clippy::mut_from_ref)]
    fn inner(&self) -> &mut Unicorn<'static, ()> {
        unsafe { &mut *self.handle.with_mut(|ptr| ptr) }
    }
}

unsafe impl Send for UnicornHandle {}
unsafe impl Sync for UnicornHandle {}

/// Wrapper around [`unicorn_engine`](unicorn_engine::Unicorn).
///
/// This struct makes a shim for unicorn that fits into a compliant version of the [`CpuBackend`] in
/// order to provide a transparent abstraction to consumer machines that might not have a cpu
/// emulated by other means yet.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct UnicornBackend {
    hook_map: StyxHookMap,
    #[derivative(Debug = "ignore")]
    arch_def: Box<dyn ArchitectureDef>,
    uc: UnicornHandle,
    stopped: bool,
    /// Was there a stop requested through [CpuBackend::stop()]?
    ///
    /// This should be accessed through [Self::stop_request_check_and_reset()] to ensure it is
    /// cleared after handling.
    stop_request: bool,
    endian: ArchEndian,
    unicorn_regions: Vec<(u64, u64, u32)>,

    /// Aggregate errors from hooks in current execution cycle.
    hook_errors: Vec<UnknownError>,

    /// Pointer to this is given to unicorn hook proxies to provide pointers for CodeHandle
    /// construction.
    ///
    /// # Safety
    ///
    /// This struct must be updated before any hook-calling invocation of unicorn, this is currently
    /// done in [UnicornBackend::execute()]. DEREFERENCING THESE POINTERS OUTSIDE OF
    /// [UnicornBackend::execute()] AND Unicorn's EXECUTION IS POTENTIALLY UNSAFE. After updating
    /// and during unicorn execution it is assumed that the containing pointers will remain valid.
    ///
    /// However, after unicorn execution we assume that the pointers are invalid as cpu, mmu, and
    /// event controller structs could be moved, there is no guarantee of these structs being pinned
    /// to their location in memory.
    #[derivative(Debug = "ignore")]
    core_ptr: Pin<Box<CorePointers>>,

    /// Holds saved registers, initially empty
    saved_context: BTreeMap<ArchRegister, RegisterValue>,
    exception: ExceptionBehavior,
    exception_requested_stop: Option<TargetExitReason>,
}

/// Holds the pointers needed to reconstruct a CoreHandle in a unicorn hook proxy.
struct CorePointers {
    unicorn_backend: *mut UnicornBackend,
    mmu: *mut Mmu,
    event_controller: *mut EventController,
    _pin: PhantomPinned,
}
impl Default for CorePointers {
    fn default() -> Self {
        Self {
            unicorn_backend: std::ptr::null_mut(),
            mmu: std::ptr::null_mut(),
            event_controller: std::ptr::null_mut(),
            _pin: PhantomPinned,
        }
    }
}
unsafe impl Send for CorePointers {}
unsafe impl Sync for CorePointers {}

/// convert from styx emulator memory permissions to unicorn memory permissions
fn styx_to_unicorn_permissions(in_perms: &MemoryPermissions) -> unicorn_const::Permission {
    let mut out: unicorn_const::Permission = unicorn_const::Permission::NONE;

    if in_perms.contains(MemoryPermissions::EXEC) {
        out |= unicorn_const::Permission::EXEC;
    }

    if in_perms.contains(MemoryPermissions::READ) {
        out |= unicorn_const::Permission::READ;
    }

    if in_perms.contains(MemoryPermissions::WRITE) {
        out |= unicorn_const::Permission::WRITE;
    }

    out
}

/// Get the Unicorn hook type, proxy function, and start/end parameters from a styx hook.
///
/// Returns None if the hook is not supported by unicorn.
fn styx_hook_to_unicorn(styx_hook: &StyxHook) -> Option<((u64, u64), HookType, *mut c_void)> {
    use hook_compat::*;
    fn range_convert(range: &AddressRange) -> (u64, u64) {
        let range = range.to_range();
        (*range.start(), *range.end())
    }

    match styx_hook {
        StyxHook::Code(range, _) => {
            Some((range_convert(range), HookType::CODE, code_hook_proxy as _))
        }
        // Block needs start/end to be 1/0
        StyxHook::Block(_) => Some(((1, 0), HookType::BLOCK, block_hook_proxy as _)),
        StyxHook::ProtectionFault(range, _) => Some((
            range_convert(range),
            HookType::MEM_PROT,
            protection_fault_hook_proxy as _,
        )),
        StyxHook::UnmappedFault(range, _) => Some((
            range_convert(range),
            HookType::MEM_UNMAPPED,
            unmapped_fault_hook_proxy as _,
        )),
        StyxHook::MemoryRead(range, _) => Some((
            range_convert(range),
            HookType::MEM_READ,
            mem_read_proxy as _,
        )),
        StyxHook::MemoryWrite(range, _) => Some((
            range_convert(range),
            HookType::MEM_WRITE,
            mem_write_proxy as _,
        )),
        // Interrupt and InvalidInstruction want start/end to be 0
        StyxHook::Interrupt(_) => Some(((0, 0), HookType::INTR, intr_hook_proxy as _)),
        StyxHook::InvalidInstruction(_) => {
            Some(((0, 0), HookType::INSN_INVALID, invalid_insn_hook_proxy as _))
        }
        _ => None,
    }
}

/// Adds a hook to the unicorn instance and the `hook_map`, safely.
fn add_unicorn_hook(
    inner: &mut Unicorn<'static, ()>,
    hook_map: &mut StyxHookMap,
    hook: StyxHook,
    state: Pin<&mut CorePointers>,
) -> Result<HookToken, AddHookError> {
    let ((start, end), typee, fnn) = styx_hook_to_unicorn(&hook)
        .with_context(|| format!("could not get unicorn hook variant of {hook:?}"))?;
    debug!("adding hook {hook:?}, start=0x{start:X}, end=0x{end:X}");

    // SAFETY: Getting &mut ref is safe since we are just passing pointer to hook for read only
    // access, the boxed item is not being moved.
    let state = unsafe { state.get_unchecked_mut() as *mut _ };
    // create the entire `CallbackBody`
    let mut callback_meta = Box::new(StyxHookDescriptor {
        styx_hook: hook,
        core: state,
    });
    // make ptr for output token
    let mut hook_token = HookToken::null_pointer();

    let token_ptr = hook_token.pointer_mut().unwrap();

    // call the unicorn ffi to add the hook
    let uc_result = unsafe {
        ffi::uc_hook_add(
            inner.get_handle(),
            token_ptr,
            typee,
            fnn,
            callback_meta.as_mut() as *mut _ as _,
            start,
            end,
        )
        .pipe(|err| UcErr::from_unicorn_trn(err, hook_token))
    };
    let token = uc_result.with_context(|| "uc_add_hook errored")?;
    if hook_token.pointer_mut().unwrap().is_null() {
        return Err(anyhow!("unicorn engine returned null pointer").into());
    }

    // pass ownership to the inner struct
    // add the callback to UnicornInner
    hook_map.add_hook(token, callback_meta)?;

    // return the index item
    Ok(token)
}

impl Hookable for UnicornBackend {
    fn add_hook(&mut self, hook: StyxHook) -> Result<HookToken, AddHookError> {
        match &hook {
            StyxHook::Code(_, _)
            | StyxHook::ProtectionFault(_, _)
            | StyxHook::UnmappedFault(_, _)
            | StyxHook::MemoryRead(_, _)
            | StyxHook::MemoryWrite(_, _)
            | StyxHook::Interrupt(_)
            | StyxHook::InvalidInstruction(_)
            | StyxHook::Block(_) => add_unicorn_hook(
                self.uc.inner(),
                &mut self.hook_map,
                hook,
                self.core_ptr.as_mut(),
            ),
            _ => Err(AddHookError::HookTypeNotSupported),
        }
    }

    fn delete_hook(&mut self, mut token: HookToken) -> Result<(), DeleteHookError> {
        let Some(token_ptr) = token.pointer_mut() else {
            warn!("non pointer token given to unicorn backend delete_hook");
            return Err(DeleteHookError::HookDoesNotExist);
        };
        let err = unsafe { ffi::uc_hook_del(self.inner().get_handle(), *token_ptr) };

        UcErr::from_unicorn(err).with_context(|| "unicorn error deleting token {token:?}")?;

        // don't delete the internal hook data until unicorn successfully
        // delete's their reference to it
        self.hook_map.delete_hook(token)?;

        Ok(())
    }
}
impl CpuBackend for UnicornBackend {
    fn read_register_raw(&mut self, reg: ArchRegister) -> Result<RegisterValue, ReadRegisterError> {
        trace!("read_reg_raw {reg}");
        let reg_value_size: RegisterValue = reg.register_value_enum();

        // the unicorn register to read
        let uc_reg = styx_to_unicorn_register(reg)?;

        let read_u64 = || {
            self.inner()
                .reg_read(uc_reg)
                .pipe(UcErr::from_unicorn_result)
                .with_context(|| format!("failed to read unicorn register {reg:?}"))
        };

        // get the data as a [`RegisterValue`]
        let output: RegisterValue = match reg_value_size {
            RegisterValue::u8(_) => read_u64()?.to_le_bytes()[0].into(),
            RegisterValue::u16(_) => {
                u16::from_le_bytes(read_u64()?.to_le_bytes()[0..2].try_into().unwrap()).into()
            }
            RegisterValue::u20(_) => u20::from_u32(u32::from_le_bytes(
                read_u64()?.to_le_bytes()[0..4].try_into().unwrap(),
            ))
            .into(),
            RegisterValue::u32(_) => {
                u32::from_le_bytes(read_u64()?.to_le_bytes()[0..4].try_into().unwrap()).into()
            }
            RegisterValue::u40(_) => {
                u40::from_le_bytes(read_u64()?.to_le_bytes()[0..5].try_into().unwrap()).into()
            }
            RegisterValue::u64(_) => read_u64()?.into(),
            RegisterValue::u80(_) => {
                let mut value = [0; 10]; // 80 bits

                // call the ffi with the raw byte array
                let err = unsafe {
                    ffi::uc_reg_read(self.inner().get_handle(), uc_reg, value.as_mut_ptr() as _)
                };

                // make sure the backend succeeded
                UcErr::from_unicorn(err)
                    .with_context(|| format!("failed to read unicorn register {reg:?}"))?;

                // make the final u80
                u80::from_le_bytes(value).into()
            }
            RegisterValue::u128(_) => {
                let mut value = [0; 16]; // 128 bits

                // call the ffi with the raw byte array
                let err = unsafe {
                    ffi::uc_reg_read(self.inner().get_handle(), uc_reg, value.as_mut_ptr() as _)
                };

                // make sure the backend succeeded
                UcErr::from_unicorn(err)
                    .with_context(|| format!("failed to read unicorn register {reg:?}"))?;

                // make the final u128
                u128::from_le_bytes(value).into()
            }
            RegisterValue::ArmSpecial(arm_special) => {
                // note: in general you'd need to match on the special enum.
                // but here we know there is only 1 possible value: the coproc access
                debug_assert!(
                    matches!(arm_special, SpecialArmRegisterValues::CoProcessor(_)),
                    "Arm special register op is not CoProcAccess"
                );

                match arm_special {
                    SpecialArmRegisterValues::CoProcessor(_) => {
                        if let ArchRegister::Special(SpecialArchRegister::Arm(
                            SpecialArmRegister::CoProcessor(r),
                        )) = reg
                        {
                            let mut value: UcArmCoprocessorRegisterAction = r.into();
                            let value_bytes: &mut [u8] = unsafe { any_as_u8_slice_mut(&mut value) };

                            debug_assert_eq!(
                                size_of::<UcArmCoprocessorRegisterAction>(),
                                value_bytes.len()
                            );

                            // call the ffi with the raw byte array
                            let err = unsafe {
                                ffi::uc_reg_read(
                                    self.inner().get_handle(),
                                    uc_reg,
                                    value_bytes.as_mut_ptr() as _,
                                )
                            };

                            // make sure the backend succeeded
                            UcErr::from_unicorn(err).with_context(|| {
                                format!("failed to read unicorn register {reg:?}")
                            })?;

                            value.into()
                        } else {
                            return Err(ReadRegisterError::Other(anyhow!(
                                "register is not a coproc register"
                            )));
                        }
                    }
                }
            }
            RegisterValue::Ppc32Special(_) => {
                return Err(ReadRegisterError::Other(anyhow!(
                    "ppc32 special register read not implemented for the unicorn backend"
                )))
            }
        };

        // re-unpack the data, and return it
        Ok(output)
    }

    fn write_register_raw(
        &mut self,
        reg: ArchRegister,
        value: RegisterValue,
    ) -> Result<(), WriteRegisterError> {
        // resolve the inputs
        trace!("write_register_raw {reg}={value}");

        //
        // at this point we know that the value will fit in
        // the size of the register
        //
        let uc_reg = styx_to_unicorn_register(reg)?;

        let write_reg_long = |value| {
            self.inner()
                .reg_write_long(uc_reg, value)
                .pipe(UcErr::from_unicorn_result)
                .with_context(|| format!("failed to write unicorn register {reg:?}"))
        };

        let write_u64 = |value| {
            self.inner()
                .reg_write(uc_reg, value)
                .pipe(UcErr::from_unicorn_result)
                .with_context(|| format!("failed to write unicorn register {reg:?}"))
        };

        // convert into the size for the backend
        // - by default unicorn takes a u64
        // - anything larger than a u64 has its own method in the ffi (reg_write_long)
        match value {
            RegisterValue::u8(u8_val) => Ok(write_u64(u8_val.into())?),
            RegisterValue::u16(u16_val) => Ok(write_u64(u16_val.into())?),
            RegisterValue::u20(u20_val) => Ok(write_u64(u20_val.into())?),
            RegisterValue::u32(u32_val) => Ok(write_u64(u32_val.into())?),
            RegisterValue::u40(u40_val) => Ok(write_u64(u40_val.into())?),
            RegisterValue::u64(u64_val) => Ok(write_u64(u64_val)?),
            RegisterValue::u80(u80_val) => Ok(write_reg_long(&u80_val.to_le_bytes())?),
            RegisterValue::u128(u128_val) => Ok(write_reg_long(&u128_val.to_le_bytes())?),
            RegisterValue::ArmSpecial(arm_special) => {
                let arch = self.architecture().architecture();

                // make sure we are executing something arm
                if arch != Arch::Arm {
                    Err(WriteRegisterError::RegisterNotAvailable(reg))
                } else {
                    let SpecialArmRegisterValues::CoProcessor(reg) = arm_special;

                    // convert the value into the unicorn format
                    let uc_reg_val: UcArmCoprocessorRegisterAction = reg.into();

                    // # Safety
                    // The type being converted to a raw pointer is `#[repr(C)]`
                    let uc_type_as_bytes = unsafe { any_as_u8_slice(&uc_reg_val) };

                    Ok(write_reg_long(uc_type_as_bytes)?)
                }
            }
            RegisterValue::Ppc32Special(_) => Err(WriteRegisterError::Other(anyhow!(
                "ppc32 special register read not implemented for the unicorn backend"
            ))),
        }
    }

    #[inline]
    fn architecture(&self) -> &dyn ArchitectureDef {
        self.arch_def.as_ref()
    }

    fn endian(&self) -> ArchEndian {
        self.endian
    }

    fn execute(
        &mut self,
        mmu: &mut Mmu,
        event_controller: &mut EventController,
        count: u64,
    ) -> Result<ExecutionReport, UnknownError> {
        // for whatever reason, the unicorn backend will not execute code at address 0.
        if self.pc().unwrap() == 0 {
            return Err(anyhow!("UnicornBackendAddressZero")).with_context(|| {
                "pc is 0, unicorn backend will not execute code at address 0
                please use another backend if this behavior is required for your usecase"
            });
        }

        trace!("starting execution @ 0x{:X}", self.pc().unwrap());
        // check if requested stop during tick
        if self.stop_request_check_and_reset() {
            return Ok(ExecutionReport::new(TargetExitReason::HostStopRequest, 0));
        }

        self.sync_regions(mmu)?;
        self.sync_core_ptr(mmu, event_controller);
        // get pc first, then start there
        let mut pc = self.inner().pc_read().pipe(UcErr::from_unicorn_result)?;

        // query mode to check any unicorn specific things before starting
        let mode = self
            .inner()
            .query(unicorn_const::Query::MODE)
            .pipe(UcErr::from_unicorn_result)
            .with_context(|| "couldn't query unicorn mode")?;
        // XXX: this is architecture specific
        // if this is in thumb mode, make sure the LSB is set
        if (mode as i32 & unicorn_const::Mode::THUMB.bits()) > 0 {
            pc |= 1;
        }
        // clamp to u64::MAX microseconds
        let timeout_micros = u64::MAX;
        let count_usize = count.clamp(0, usize::MAX as u64) as usize;

        // we are running now
        self.set_running();

        // start emulation at pc
        let uc_exit_reason = self.inner().emu_start(pc, 0, timeout_micros, count_usize);

        // no longer running, set stopped
        self.set_stopped();

        trace!("exit: {uc_exit_reason:?}");

        // handle the exit condition
        match uc_exit_reason {
            // we hit the timeout or the instruction count limit
            Ok(_) => {
                // figure out if we hit the instruction count or the timeout
                if !self.hook_errors.is_empty() {
                    let errors = std::mem::replace(&mut self.hook_errors, Vec::with_capacity(10));
                    let wrapped_error: Result<(), UnknownError> =
                        errors.into_iter().map(Err).bcollect();
                    Err(wrapped_error.unwrap_err())
                } else if let Some(exit_reason) = self.exception_requested_stop.clone() {
                    self.exception_requested_stop = None;
                    Ok(ExecutionReport::unknown_instruction_count(exit_reason))
                } else if self.stop_request_check_and_reset() {
                    Ok(ExecutionReport::unknown_instruction_count(
                        TargetExitReason::HostStopRequest,
                    ))
                } else if self.instruction_count_met() {
                    Ok(ExecutionReport::new(
                        TargetExitReason::InstructionCountComplete,
                        count,
                    ))
                } else {
                    Err(anyhow!("unicorn.emu_start returned okay but did not complete instruction count or timeout"))
                }
            }
            // an error was tripped by either the target or the host
            Err(err) => match TryInto::<TargetExitReason>::try_into(err) {
                Ok(exit_reason) => Ok(ExecutionReport::unknown_instruction_count(exit_reason)),
                Err(_) => Err(anyhow!("unknown unicorn error {err:?}")),
            },
        }
    }

    fn stop(&mut self) {
        self.request_stop();

        self.inner()
            .emu_stop()
            .expect("failed to stop unicorn backend");
    }

    fn pc(&mut self) -> Result<u64, UnknownError> {
        Ok(self.inner().pc_read().pipe(UcErr::from_unicorn_result)?)
    }

    fn set_pc(&mut self, value: u64) -> Result<(), UnknownError> {
        Ok(self
            .inner()
            .set_pc(value)
            .pipe(UcErr::from_unicorn_result)?)
    }

    fn context_save(&mut self) -> Result<(), UnknownError> {
        self.saved_context.clear();

        for register in self.architecture().registers().registers() {
            let val = self.read_register_raw(register.variant())?;
            self.saved_context.insert(register.variant(), val);
        }

        Ok(())
    }

    fn context_restore(&mut self) -> Result<(), UnknownError> {
        if self.saved_context.is_empty() {
            return Err(anyhow!("attempting to restore from nothing"));
        }

        for register in self.architecture().registers().registers() {
            self.write_register_raw(
                register.variant(),
                *self.saved_context.get(&register.variant()).unwrap(),
            )?;
        }

        Ok(())
    }
}

#[derive(RefCast)]
#[repr(transparent)]
struct UcPerms(unicorn_engine::Permission);
impl PartialEq<MemoryPermissions> for UcPerms {
    fn eq(&self, other: &MemoryPermissions) -> bool {
        self.0.bits() == other.bits()
    }
}

#[derive(RefCast)]
#[repr(transparent)]
struct UcRegion(MemRegion);
impl PartialEq<MemoryRegion> for UcRegion {
    fn eq(&self, other: &MemoryRegion) -> bool {
        self.0.begin == other.start()
            && self.0.end == other.end()
            && self.0.perms.pipe_ref(UcPerms::ref_cast) == &other.perms()
    }
}

impl UnicornBackend {
    /// called to indicate a hook has encountered a fatal error.
    fn hook_error(&mut self, error: UnknownError) {
        self.hook_errors.push(error);
        self.inner()
            .emu_stop()
            .expect("failed to stop unicorn backend");
    }

    /// Updates [Self::core_ptr]. Called at beginning of [Self::execute()].
    fn sync_core_ptr(&mut self, mmu: &mut Mmu, ev: &mut EventController) {
        let self_ptr = self as *mut _;
        self.core_ptr.set(CorePointers {
            unicorn_backend: self_ptr,
            mmu: mmu as *mut _,
            event_controller: ev as *mut _,
            _pin: PhantomPinned,
        });
    }

    /// Ensures unicorn regions match the mmu regions in styx.
    ///
    /// For performance we keep a list of unicorn regions in [Self::unicorn_regions] to compare
    /// against the current mmu regions. If these do not match, we remove all unicorn regions and
    /// overwrite them with the current mmu regions.
    ///
    /// We assume that Unicorn regions will not change outside of these functions.
    fn sync_regions(&mut self, mmu: &mut Mmu) -> Result<(), UnknownError> {
        if !self.check_synced(mmu)? {
            debug!("unicorn region not synced, resyncing");
            self.overwrite_regions(mmu)?;
        }
        Ok(())
    }

    /// Returns true if the mmu regions match the [Self::unicorn_regions].
    fn check_synced(&self, mmu: &mut Mmu) -> Result<bool, UnknownError> {
        let uc_regions = self.unicorn_regions.iter().cloned();

        let mmu_regions = mmu
            .regions()
            .ok_or(anyhow!("unicorn backend requires region physical memory"))?;
        let mmu_regions = mmu_regions.into_iter().map(|r| {
            (
                r.base(),
                r.size(),
                styx_to_unicorn_permissions(&r.perms).bits(),
            )
        });

        Ok(uc_regions.eq(mmu_regions))
    }

    /// Removes all unicorn regions and overwrites them with the current mmu regions.
    fn overwrite_regions(&mut self, mmu: &mut Mmu) -> Result<(), UnknownError> {
        trace!("syncing regions");
        self.unicorn_regions.clear();
        let uc_regions = self
            .inner()
            .mem_regions()
            .pipe(UcErr::from_unicorn_result)?;
        let mmu_regions = mmu
            .regions()
            .ok_or(anyhow!("unicorn backend requires region physical memory"))?;

        for uc_region in uc_regions {
            let address = uc_region.begin;
            let size = (uc_region.end - uc_region.begin) as usize + 1;
            trace!("unicorn unmap {address:X}:{size:X}");
            self.inner()
                .mem_unmap(address, size)
                .pipe(UcErr::from_unicorn_result)
                .with_context(|| "failed to unmap")?;
        }
        for region in mmu_regions {
            // check region.base + region.size to be page aligned
            region
                .expect_aligned(0x1000)
                .with_context(|| "unicorn memory regions must be 4k aligned ")?;

            let perms = styx_to_unicorn_permissions(&region.perms);

            // # Safety
            // Until a better method is found, we're making sure
            // that the buffer size we get back is page aligned.
            // We're also keeping the [`MemoryRegion`] around so we
            // know it's not dead until we get dropped.
            unsafe {
                let (data, size) = (region.data.as_mut_ptr(), region.size());

                // if we call unicorn to add a region with size 0, it will error
                if size > 0 {
                    // cast to the void pointer required by unicorn, note
                    // that we're just unwrapping, at some point we're going
                    // to need to actually handle the unicorn errors.
                    self.inner()
                        .mem_map_ptr(
                            region.base(),
                            size as usize,
                            perms,
                            data as *mut std::ffi::c_void,
                        )
                        .pipe(UcErr::from_unicorn_result)?;
                }
            }

            trace!("region: {:?}", region.size());
            self.unicorn_regions
                .push((region.base(), region.size(), perms.bits()));
        }
        trace!("syncing regions done");
        Ok(())
    }

    /// sets up a unicorn backend with the corresponding architecture
    /// and the relevant endianness + architecture modes
    pub fn new_engine(
        arch: Arch,
        arch_variant: impl Into<ArchVariant>,
        endian: ArchEndian,
    ) -> UnicornBackend {
        Self::new_engine_exception(arch, arch_variant, endian, ExceptionBehavior::default())
    }

    pub fn new_engine_exception(
        arch: Arch,
        arch_variant: impl Into<ArchVariant>,
        endian: ArchEndian,
        exception: ExceptionBehavior,
    ) -> UnicornBackend {
        let arch_variant = arch_variant.into();
        // derive the styx architecture metadata from the enum passed in
        // the first `.into()` converts into the `ArchVariant`,
        // the clone is required since complex arch variants can exist
        // the second does the final conversion into an `ArchitectureDef`
        let arch_def: Box<dyn ArchitectureDef> = arch_variant.clone().into();

        // get the unicorn specific options required for the architecture
        let (uc_arch, uc_mode, uc_model) =
            styx_to_unicorn_machine(arch, arch_variant, endian).unwrap();

        // setup the correct unicorn instance
        let uc = Unicorn::new(uc_arch, uc_mode).unwrap();
        uc.ctl_set_cpu_model(uc_model).unwrap();

        UnicornBackend {
            hook_map: StyxHookMap::default(),
            arch_def,
            uc: UnicornHandle::new(uc),
            // the backend should initially be in the stopped state
            stopped: true,
            stop_request: false,
            endian,
            core_ptr: Box::pin(CorePointers::default()),
            hook_errors: Vec::with_capacity(10),
            unicorn_regions: Vec::new(),
            saved_context: BTreeMap::default(),
            exception,
            exception_requested_stop: None,
        }
    }

    /// This method allows us to have a rust callback system
    /// that gets invoked by a C-runtime. Using an [`UnsafeCell`]
    /// we hold a reference to our inner rust struct that invokes
    /// the unicorn api to drive the C-runtime.
    ///
    /// # Safety
    /// This is used to modify the internal struct. This should
    /// be used only to start, stop, and modify the unicorn state.
    /// The &mut returned from this method should never be passed
    /// around.
    ///
    /// TODO: make this method `unsafe`
    #[allow(clippy::mut_from_ref)]
    fn inner(&self) -> &mut Unicorn<'static, ()> {
        self.uc.inner()
    }

    /// Checks if the unicorn engine has exited due to executing its provided
    /// instruction count
    ///
    /// This method assumes that the cpu is stopped (does not check),
    /// and reports the status according to our 2 atomic booleans used to determine
    /// stop state
    ///
    /// | `self.stopped` | `self.stop_request` | meaning |
    /// |----------------|---------------------|---------|
    /// | false          | false               | X (false) |
    /// | false          | true                | X (false) |
    /// | true           | false               | true, cpu stopped, and was not requested. implies insn count met|
    /// | true           | true                | false, cpu stopped, was requested. implies insn count not met |
    #[inline]
    fn instruction_count_met(&self) -> bool {
        self.stopped && !self.stop_request
    }

    #[inline]
    fn set_stopped(&mut self) {
        self.stopped = true;
    }

    #[inline]
    fn set_running(&mut self) {
        self.stopped = false;
        self.stop_request = false;
    }

    #[inline]
    fn request_stop(&mut self) {
        self.stop_request = true;
    }

    #[inline]
    fn stop_request_check_and_reset(&mut self) -> bool {
        let res = self.stop_request;
        self.stop_request = false;
        res
    }
}

#[cfg(test)]
mod tests {
    use keystone_engine::Keystone;
    use styx_cpu_type::arch::arm::{ArmRegister, ArmVariants};
    use styx_processor::{
        cpu::CpuBackendExt,
        hooks::{CoreHandle, MemFaultData, Resolution},
        memory::{
            helpers::{ReadExt, WriteExt},
            MemoryPermissions,
        },
    };

    use super::*;

    /// Test fixture that uses arm32le executor to test parts of the runtime
    struct TestMachine {
        pub proc: UnicornBackend,
        pub mmu: Mmu,
        pub ev: EventController,
        instruction_count: u32,
    }

    impl TestMachine {
        fn with_bytes(code: &[u8], num_instr: u32) -> Self {
            let mut backend = UnicornBackend::new_engine(
                Arch::Arm,
                ArmVariants::ArmCortexM4,
                ArchEndian::LittleEndian,
            );
            let mut mmu = Mmu::default_region_store();
            let ev = EventController::default();

            mmu.memory_map(0x4000, 0x1000, MemoryPermissions::all())
                .unwrap();

            // Write generated instructions to memory
            mmu.code().write(0x4000).bytes(code).unwrap();
            // Start thumb execution at our instructions
            backend.write_register(ArmRegister::Pc, 0x4001u32).unwrap();

            // get pc
            assert_eq!(0x4000, backend.pc().unwrap(), "pc is not correct");
            let pc_val: u32 = backend.read_register::<u32>(ArmRegister::Pc).unwrap();
            assert_eq!(0x4000, pc_val, "did not read pc correctly");

            TestMachine {
                proc: backend,
                mmu,
                ev,
                instruction_count: num_instr,
            }
        }
        fn with_code(instr: &str) -> Self {
            // Assemble instructions
            // Processor default to thumb so we use that
            let ks = Keystone::new(keystone_engine::Arch::ARM, keystone_engine::Mode::THUMB)
                .expect("Could not initialize Keystone engine");
            let asm = ks
                .asm(instr.to_owned(), 0x4000)
                .expect("Could not assemble");
            let code = asm.bytes;
            let instruction_count = asm.stat_count;

            Self::with_bytes(&code, instruction_count)
        }
        fn run_no_assert(&mut self) -> TargetExitReason {
            self.proc
                .execute(&mut self.mmu, &mut self.ev, self.instruction_count.into())
                .unwrap()
                .exit_reason
        }

        fn run(&mut self) {
            let exit_reason = self.run_no_assert();

            assert_eq!(exit_reason, TargetExitReason::InstructionCountComplete);
        }

        fn run_and_assert_exit_reason(&mut self, reason: TargetExitReason) {
            let exit_reason = self.run_no_assert();

            assert_eq!(exit_reason, reason);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_save_restore_registers() {
        let mut machine = TestMachine::with_code("movs r2, #10;movs r2, #20;");

        // execute first instruction, check if r2=10, save state
        machine
            .proc
            .execute(&mut machine.mmu, &mut machine.ev, 1)
            .unwrap();
        assert_eq!(
            machine.proc.read_register::<u32>(ArmRegister::R2).unwrap(),
            10
        );
        machine.proc.context_save().unwrap();

        // execute next instruction, check if r2=20
        machine
            .proc
            .execute(&mut machine.mmu, &mut machine.ev, 1)
            .unwrap();
        assert_eq!(
            machine.proc.read_register::<u32>(ArmRegister::R2).unwrap(),
            20
        );

        // do a context restore, check if r2=10 again
        machine.proc.context_restore().unwrap();
        assert_eq!(
            machine.proc.read_register::<u32>(ArmRegister::R2).unwrap(),
            10
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_hook_error() {
        // Tests when a hook returns an error. The backend should propagate it up.
        let mut machine = TestMachine::with_code("movw r1, #0x400b;mov r8, r8;mov r8,r8;bx r1");

        let cb = |proc: CoreHandle, addr: u64, size: u32| {
            println!("hit bb: 0x{:x} of size: {}", addr, size);

            let r2 = proc.cpu.read_register::<u32>(ArmRegister::R2).unwrap() + 1;
            proc.cpu.write_register(ArmRegister::R2, r2).unwrap();
            Err(anyhow!("bad error!"))
        };

        machine
            .proc
            .add_hook(StyxHook::Block(Box::new(cb)))
            .unwrap();

        let res = machine.proc.execute(&mut machine.mmu, &mut machine.ev, 100);

        assert!(res.is_err(), "{res:?} not an error!");
        assert_eq!(
            machine.proc.read_register::<u32>(ArmRegister::R2).unwrap(),
            1
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_address_zero_error() {
        // Tests that unicorn backend returns an error at address 0
        let mut machine = TestMachine::with_code("movw r1, #0x400b;mov r8, r8;mov r8,r8;bx r1");

        // set pc to 0
        machine.proc.set_pc(0).unwrap();
        let res = machine.proc.execute(&mut machine.mmu, &mut machine.ev, 100);

        assert!(res.is_err(), "{res:?} not an error!");
        assert_eq!(
            machine.proc.read_register::<u32>(ArmRegister::Pc).unwrap(),
            0
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_invalid_insn_hooks() {
        // Tests that the invalid instruction hook gets executed when valid code gets
        // overwritten with intentionally bad data. This test clobbers the end of this
        // while true insn data to provide invalid opcodes starting @ 0x4004
        let mut machine = TestMachine::with_code("movw r1, #0x400b;mov r8, r8;mov r8,r8;bx r1");

        // write invalid data to 0x4004 (after 2 insns in)
        machine
            .mmu
            .code()
            .write(0x4004)
            .bytes(&[0xff, 0xff, 0xff, 0xff])
            .unwrap();

        let cb = |proc: CoreHandle| {
            println!("hit invalid insn @ pc: {:#x}", proc.cpu.pc().unwrap());

            proc.cpu.write_register(ArmRegister::R4, 3u32).unwrap();

            // "keep searching other callbacks"
            Ok(Resolution::NotFixed)
        };

        let token1 = machine
            .proc
            .add_hook(StyxHook::InvalidInstruction(Box::new(cb)))
            .unwrap();

        // asserts we get an insn decode error
        // reasoning:
        //  - both callbacks return "false", meaning they did not handle the error
        //  - unicorn runs out of callbacks, so it propagates the error
        machine.run_and_assert_exit_reason(TargetExitReason::InstructionDecodeError);
        // where we put the bad data
        assert_eq!(0x4004, machine.proc.pc().unwrap());

        let r4_val = machine.proc.read_register::<u32>(ArmRegister::R4).unwrap();
        assert_eq!(r4_val, 3, "cb failed");

        machine.proc.delete_hook(token1).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_bb_hooks() {
        // tests that the basic block hook event will fire when this while true
        // loop is translated then executed
        let mut machine = TestMachine::with_code("movw r1, #0x400b;mov r8, r8;mov r8,r8;bx r1");

        let cb = |proc: CoreHandle, addr: u64, size: u32| {
            println!("hit bb: 0x{:x} of size: {}", addr, size);

            let r2 = proc.cpu.read_register::<u32>(ArmRegister::R2).unwrap() + 1;
            proc.cpu.write_register(ArmRegister::R2, r2).unwrap();
            Ok(())
        };

        machine
            .proc
            .add_hook(StyxHook::Block(Box::new(cb)))
            .unwrap();

        machine.run();

        assert_eq!(
            machine.proc.read_register::<u32>(ArmRegister::R2).unwrap(),
            2
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_unmapped_read_hooks() {
        // tests that the hook gets called when we read from an unmapped address
        let mut machine = TestMachine::with_code("movw r1, #0x9999;ldr r4, [r1];");

        let cb = |proc: CoreHandle, addr: u64, size: u32, fault_data: MemFaultData| {
            println!(
                "unmapped fault: 0x{:x} of size: {}, type: {:?}",
                addr, size, fault_data
            );

            proc.cpu.write_register(ArmRegister::R2, 1u32).unwrap();

            Ok(Resolution::NotFixed)
        };

        // insert hooks and collect tokens for removal later
        let token1 = machine
            .proc
            .add_hook(StyxHook::unmapped_fault(.., cb))
            .unwrap();

        // both callback return `false`, so emulation should also exit
        // with an UnmappedMemoryRead error
        machine.run_and_assert_exit_reason(TargetExitReason::UnmappedMemoryRead);

        let end_pc = machine.proc.pc().unwrap();

        // basic assertions are correct
        assert_eq!(
            0x4004u64, end_pc,
            "Stopped at incorrect instruction: {:#x}",
            end_pc,
        );
        assert_eq!(
            0x9999,
            machine.proc.read_register::<u32>(ArmRegister::R1).unwrap(),
            "r1 is incorrect immediate value",
        );

        // assertions to test that the hooks we successfully called
        assert_eq!(
            1,
            machine.proc.read_register::<u32>(ArmRegister::R2).unwrap(),
            "normal hook failed"
        );

        // removal of hooks is correct
        machine.proc.delete_hook(token1).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_unmapped_write_hooks() {
        // tests that the hook gets called when we write to an unmapped address
        let mut machine = TestMachine::with_code("movw r1, #0x9999;str r4, [r1];");

        let cb = |proc: CoreHandle, addr: u64, size: u32, fault_data: MemFaultData| {
            println!(
                "unmapped fault: 0x{:x} of size: {}, type: {:?}",
                addr, size, fault_data
            );

            proc.cpu.write_register(ArmRegister::R2, 1u32).unwrap();

            Ok(Resolution::NotFixed)
        };

        // insert hooks and collect tokens for removal later
        let token1 = machine
            .proc
            .add_hook(StyxHook::unmapped_fault(.., cb))
            .unwrap();

        // both callback return `false`, so emulation should also exit
        // with an UnmappedMemoryWrite error
        machine.run_and_assert_exit_reason(TargetExitReason::UnmappedMemoryWrite);

        let end_pc = machine.proc.pc().unwrap();

        // basic assertions are correct
        assert_eq!(
            0x4004u64, end_pc,
            "Stopped at incorrect instruction: {:#x}",
            end_pc,
        );
        assert_eq!(
            0x9999,
            machine.proc.read_register::<u32>(ArmRegister::R1).unwrap(),
            "r1 is incorrect immediate value",
        );

        // assertions to test that the hooks we successfully called
        assert_eq!(
            1,
            machine.proc.read_register::<u32>(ArmRegister::R2).unwrap(),
            "normal hook failed"
        );

        // removal of hooks is correct
        machine.proc.delete_hook(token1).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_protection_read_hooks() {
        // tests that the hook gets called when we read from a WO address
        let mut machine = TestMachine::with_code("movw r1, #0x9999;ldr r4, [r1];");

        // map in 0x9999 as write only
        machine
            .mmu
            .add_memory_region(MemoryRegion::new(0x9000, 0x1000, MemoryPermissions::WRITE).unwrap())
            .unwrap();

        let cb = |proc: CoreHandle,
                  addr: u64,
                  size: u32,
                  perms: MemoryPermissions,
                  fault_data: MemFaultData| {
            println!(
                "protection fault: 0x{:x} of size: {}, type: {:?}",
                addr, size, fault_data
            );

            println!("region has permissions: {}", perms);

            proc.cpu.write_register(ArmRegister::R2, 1u32).unwrap();

            Ok(Resolution::NotFixed)
        };

        // insert hooks and collect tokens for removal later
        let token1 = machine
            .proc
            .add_hook(StyxHook::protection_fault(.., cb))
            .unwrap();

        // both callback return `false`, so emulation should also exit
        // with an ProtectedMemoryRead error
        machine.run_and_assert_exit_reason(TargetExitReason::ProtectedMemoryRead);

        let end_pc = machine.proc.pc().unwrap();

        // basic assertions are correct
        assert_eq!(
            0x4004u64, end_pc,
            "Stopped at incorrect instruction: {:#x}",
            end_pc,
        );
        assert_eq!(
            0x9999,
            machine.proc.read_register::<u32>(ArmRegister::R1).unwrap(),
            "r1 is incorrect immediate value",
        );

        // assertions to test that the hooks we successfully called
        assert_eq!(
            1,
            machine.proc.read_register::<u32>(ArmRegister::R2).unwrap(),
            "normal hook failed"
        );

        // removal of hooks is correct
        machine.proc.delete_hook(token1).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_protection_write_hooks() {
        // tests that the hook gets called when we write to a RO address
        let mut machine = TestMachine::with_code("movw r1, #0x9999;str r4, [r1];");

        // map in 0x9999 as read only
        machine
            .mmu
            .add_memory_region(MemoryRegion::new(0x9000, 0x1000, MemoryPermissions::READ).unwrap())
            .unwrap();

        let cb = |proc: CoreHandle,
                  addr: u64,
                  size: u32,
                  perms: MemoryPermissions,
                  fault_data: MemFaultData| {
            println!(
                "protection fault: 0x{:x} of size: {}, type: {:?}",
                addr, size, fault_data
            );

            println!("region has permissions: {}", perms);

            proc.cpu.write_register(ArmRegister::R2, 1u32).unwrap();

            Ok(Resolution::NotFixed)
        };

        // insert hooks and collect tokens for removal later
        let token1 = machine
            .proc
            .add_hook(StyxHook::protection_fault(.., cb))
            .unwrap();

        // both callback return `false`, so emulation should also exit
        // with an ProtectedMemoryWrite error
        machine.run_and_assert_exit_reason(TargetExitReason::ProtectedMemoryWrite);

        let end_pc = machine.proc.pc().unwrap();

        // basic assertions are correct
        assert_eq!(
            0x4004u64, end_pc,
            "Stopped at incorrect instruction: {:#x}",
            end_pc,
        );
        assert_eq!(
            0x9999,
            machine.proc.read_register::<u32>(ArmRegister::R1).unwrap(),
            "r1 is incorrect immediate value",
        );

        // assertions to test that the hooks we successfully called
        assert_eq!(
            1,
            machine.proc.read_register::<u32>(ArmRegister::R2).unwrap(),
            "normal hook failed"
        );

        // removal of hooks is correct
        machine.proc.delete_hook(token1).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_all_hook_types() {
        // Tests every hook type, adding, executing, and deleting.
        //
        // All callbacks increment R4 as a way to keep track of the
        // total number of times the hooks were triggered.

        let code = [
            // little endian
            0xa0, 0xf1, 0x17, 0x00, // sub r0, #23
            0x42, 0xF2, 0x00, 0x00, // movw r0, #0x2000
            0x00, 0x68, // ldr  r0, [r0]
            0x42, 0xF2, 0x04, 0x07, // movw r7, #0x2004
            0x3F, 0x60, // str r7, [r7]
            0x00, 0xdf, // svc 0
        ];

        let mut machine = TestMachine::with_bytes(&code, 6);

        // map a region with known data, and the messed up address

        machine
            .mmu
            .memory_map(0x2000, 0x1000, MemoryPermissions::all())
            .unwrap();

        let code_cb = |proc: CoreHandle| {
            println!("code hook @0x{:x}", proc.cpu.pc().unwrap());
            let new_r4 = proc.cpu.read_register::<u32>(ArmRegister::R4).unwrap() + 1;
            proc.cpu.write_register(ArmRegister::R4, new_r4).unwrap();
            Ok(())
        };

        let mem_read_cb = |proc: CoreHandle, address: u64, size: u32, data: &mut [u8]| {
            println!(
                "Memory read from address: {:x}, with size: {} and data: {:?}",
                address, size, data
            );
            let new_r4 = proc.cpu.read_register::<u32>(ArmRegister::R4).unwrap() + 1;
            proc.cpu.write_register(ArmRegister::R4, new_r4).unwrap();
            Ok(())
        };

        let mem_write_cb = |proc: CoreHandle, address: u64, size: u32, data: &[u8]| {
            println!(
                "Memory write to address: {:x}, with size: {} and data: {:?}",
                address, size, data
            );
            let new_r4 = proc.cpu.read_register::<u32>(ArmRegister::R4).unwrap() + 1;
            proc.cpu.write_register(ArmRegister::R4, new_r4).unwrap();
            Ok(())
        };

        let intr_cb = |proc: CoreHandle, intno: i32| {
            println!("caught interrupt: {}", intno);
            proc.cpu.stop();
            let new_r4 = proc.cpu.read_register::<u32>(ArmRegister::R4).unwrap() + 1;
            proc.cpu.write_register(ArmRegister::R4, new_r4).unwrap();
            Ok(())
        };

        let code_token = machine
            .proc
            .add_hook(StyxHook::code(0x4000..=0x4000, code_cb))
            .unwrap();
        let mem_read_token = machine
            .proc
            .mem_read_hook(0x2000, 0x2004, Box::new(mem_read_cb))
            .unwrap();
        let mem_write_token = machine
            .proc
            .mem_write_hook(0x2004, 0x2008, Box::new(mem_write_cb))
            .unwrap();
        let intr_token = machine.proc.add_hook(StyxHook::interrupt(intr_cb)).unwrap();

        machine.proc.set_pc(0x4001).unwrap();

        // check
        machine.run_and_assert_exit_reason(TargetExitReason::HostStopRequest);

        machine.proc.delete_hook(code_token).unwrap();
        machine.proc.delete_hook(mem_read_token).unwrap();
        machine.proc.delete_hook(mem_write_token).unwrap();
        machine.proc.delete_hook(intr_token).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_interrupt_hook() {
        // tests that software raised interrupt executes an interrupt hook to
        // be called, in this case svc0 for arm32le
        let code: [u8; 2] = [0x00, 0xdf];
        let mut machine = TestMachine::with_bytes(&code, 1);

        let cb = |proc: CoreHandle, intno: i32| {
            println!("caught interrupt: {}", intno);
            proc.cpu.stop();
            Ok(())
        };

        let handle = machine.proc.add_hook(StyxHook::interrupt(cb)).unwrap();

        // run
        machine
            .proc
            .write_register(ArmRegister::Pc, 0x4001u32)
            .unwrap();
        machine.run_and_assert_exit_reason(TargetExitReason::HostStopRequest);

        machine.proc.delete_hook(handle).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_generic_add_hook() {
        let code: [u8; 4] = [0xa0, 0xf1, 0x17, 0x00]; // sub r0, #23 in LE

        let mut machine = TestMachine::with_bytes(&code, 1);

        let cb = |proc: CoreHandle| {
            proc.cpu.set_pc(0x4500).unwrap();
            Ok(())
        };

        let token = machine
            .proc
            .add_hook(StyxHook::code(0x4000u64..=0x4000u64, cb))
            .unwrap();

        // run
        machine
            .proc
            .write_register(ArmRegister::Pc, 0x4001u32)
            .unwrap();
        machine.run_no_assert();

        assert_eq!(machine.proc.pc().unwrap(), 0x4500);

        machine.proc.delete_hook(token).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_delete_hook() {
        // tests that we can delete a hook before actually executing
        // any code
        let mut machine = TestMachine::with_bytes(&[], 0);

        let handle = machine
            .proc
            .add_hook(StyxHook::code(.., |_proc: CoreHandle| Ok(())))
            .unwrap();

        // will panic on error
        machine.proc.delete_hook(handle).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_call_deleted_hook() {
        // adds a hook, checks to make sure it gets called
        // then deletes the hook and makes sure it doesn't get called
        let code: [u8; 2] = [0xfe, 0xe7]; // b #0
        let mut machine = TestMachine::with_bytes(&code, 1);

        let cb = |proc: CoreHandle| {
            proc.cpu.stop();
            Ok(())
        };

        let handle = machine.proc.add_hook(StyxHook::code(.., cb)).unwrap();

        let exit_reason = machine
            .proc
            .execute(&mut machine.mmu, &mut machine.ev, 0)
            .unwrap()
            .exit_reason;
        assert_eq!(exit_reason, TargetExitReason::HostStopRequest);

        machine.proc.delete_hook(handle).unwrap();

        let exit_reason = machine
            .proc
            .execute(&mut machine.mmu, &mut machine.ev, 10)
            .unwrap()
            .exit_reason;
        assert_eq!(exit_reason, TargetExitReason::InstructionCountComplete);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_correct_exit_status() {
        // infinite loop code to test timeout exit
        let code: [u8; 2] = [0xfe, 0xe7]; // b #0

        let mut machine = TestMachine::with_bytes(&code, 1);

        machine.run_and_assert_exit_reason(TargetExitReason::InstructionCountComplete);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)] // unicorn leaks memory
    fn test_improper_usage_of_hook() {
        // init backend
        let mut backend = UnicornBackend::new_engine(
            Arch::Arm,
            ArmVariants::ArmCortexM4,
            ArchEndian::LittleEndian,
        );

        // panics if error
        backend
            .add_hook(StyxHook::code(0..=0, |_proc: CoreHandle| Ok(())))
            .unwrap();
    }

    #[test]
    fn test_styx_to_unicorn_opts() {
        let arm_arch = Arch::Arm;
        let cortex_m4 = ArmVariants::ArmCortexM4;
        let little_endian = ArchEndian::LittleEndian;

        // TODO: once unicorn upstream issues wrt cpu_model have been
        // resolved...set `uc_model`
        let (uc_arch, uc_mode, _) =
            styx_to_unicorn_machine(arm_arch, cortex_m4, little_endian).unwrap();

        assert_eq!(uc_arch, unicorn_const::Arch::ARM);
        assert_eq!(uc_mode.bits(), unicorn_const::Mode::LITTLE_ENDIAN.bits());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_initialize_unicorn_backend() {
        let thumb = Arch::Arm;
        let le = ArchEndian::LittleEndian;

        // panic in here if error
        let _uc_backend = UnicornBackend::new_engine(thumb, ArmVariants::ArmCortexM4, le);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)] // unicorn leaks memory
    fn test_unicorn_write_read_regs() {
        let r3_value: u32 = 0x41414141;
        let register = ArmRegister::R3;

        // init backend
        let mut backend = UnicornBackend::new_engine(
            Arch::Arm,
            ArmVariants::ArmCortexM4,
            ArchEndian::LittleEndian,
        );

        // write register value
        backend.write_register(register, r3_value).unwrap();

        // read register value
        let read_value = backend.read_register::<u32>(register).unwrap();

        // make sure register value is the same
        assert_eq!(r3_value, read_value);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)] // unicorn leaks memory
    fn test_unicorn_map_memory() {
        let code: [u8; 4] = [0xa0, 0xf1, 0x17, 0x00]; // sub r0, #23 in LE

        let mut machine = TestMachine::with_bytes(&code, 1);

        // make sure can read the data
        let out_buf = machine.mmu.code().read(0x4000).vec(4).unwrap();
        assert_eq!(&code, out_buf.as_slice());
    }

    /// callback to change pc to 0x99990000
    fn mess_up_pc_callback(backend: CoreHandle) -> Result<(), UnknownError> {
        println!("mess_up_pc_callback");
        backend
            .cpu
            .write_register(ArmRegister::Pc, 0x99990000u32)
            .unwrap();
        Ok(())
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)] // unicorn leaks memory
    fn test_unicorn_run_add_hook() {
        let code: [u8; 4] = [0xa0, 0xf1, 0x17, 0x00]; // sub r0, #23 in LE

        let mut machine = TestMachine::with_bytes(&code, 1);

        // map a region with known data, and the messed up address
        machine
            .mmu
            .add_memory_region(
                MemoryRegion::new(0x99990000, 0x1000, MemoryPermissions::all()).unwrap(),
            )
            .unwrap();

        // set hook to trigger
        let token = machine
            .proc
            .add_hook(StyxHook::code(0x4000u64..=0x4000u64, mess_up_pc_callback))
            .unwrap();

        // run
        machine.run_no_assert();

        // make sure hook fire
        let pc_val = machine.proc.read_register::<u32>(ArmRegister::Pc).unwrap();
        assert_eq!(pc_val, 0x99990000);
        machine.proc.delete_hook(token).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)] // unicorn leaks memory
    fn test_unicorn_run_trace() {
        let code: [u8; 4] = [0xa0, 0xf1, 0x17, 0x00]; // sub r0, #23 in LE

        let mut machine = TestMachine::with_bytes(&code, 1);

        // run, set r0 to 123, should get #23 subtracted from it
        machine
            .proc
            .write_register(ArmRegister::R0, 123u32)
            .unwrap();
        machine
            .proc
            .write_register(ArmRegister::Pc, 0x4001u32)
            .unwrap();
        machine.run();

        // make sure pc at end and r0 == 123 - 23
        let pc_val = machine.proc.read_register::<u32>(ArmRegister::Pc).unwrap();
        let r0_val = machine.proc.read_register::<u32>(ArmRegister::R0).unwrap();
        assert_eq!(pc_val, 0x4004);
        assert_eq!(r0_val, 100);
    }

    #[test]
    fn test_unicorn_permissions_convert() {
        // test None == None
        let none_bits = styx_to_unicorn_permissions(&MemoryPermissions::empty());
        assert_eq!(none_bits.bits(), unicorn_const::Permission::NONE.bits());

        // test exec == exec
        let exec_bits = styx_to_unicorn_permissions(&MemoryPermissions::EXEC);
        assert_eq!(exec_bits.bits(), unicorn_const::Permission::EXEC.bits());

        // test read == read
        let read_bits = styx_to_unicorn_permissions(&MemoryPermissions::READ);
        assert_eq!(read_bits.bits(), unicorn_const::Permission::READ.bits());

        // test write == write
        let write_bits = styx_to_unicorn_permissions(&MemoryPermissions::WRITE);
        assert_eq!(write_bits.bits(), unicorn_const::Permission::WRITE.bits());

        // test R/W == R/W
        let rw_perms =
            styx_to_unicorn_permissions(&MemoryPermissions::READ.union(MemoryPermissions::WRITE));
        let rw_bits = unicorn_const::Permission::READ | unicorn_const::Permission::WRITE;
        assert_eq!(rw_perms.bits(), rw_bits.bits());

        // test E/R == E/R
        let er_perms =
            styx_to_unicorn_permissions(&MemoryPermissions::READ.union(MemoryPermissions::EXEC));
        let er_bits = unicorn_const::Permission::READ | unicorn_const::Permission::EXEC;
        assert_eq!(er_perms.bits(), er_bits.bits());

        // test ALL == ALL
        let all_perms = styx_to_unicorn_permissions(&MemoryPermissions::all());
        assert_eq!(all_perms.bits(), unicorn_const::Permission::ALL.bits());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_code_hook_execution_order() {
        styx_util::logging::init_logging();
        // Ensures that code hooks are triggered BEFORE instruction is executed
        let mut machine = TestMachine::with_code("mov r1, r0");

        machine
            .proc
            .write_register(ArmRegister::R0, 0xCAFEBABEu32)
            .unwrap();
        machine
            .proc
            .write_register(ArmRegister::R1, 0xDEADFACEu32)
            .unwrap();

        let code_cb = |proc: CoreHandle| {
            let r1_value = proc.cpu.read_register::<u32>(ArmRegister::R1).unwrap();
            println!("checking instruction not applied");
            // Check instruction is not applied
            assert_eq!(r1_value, 0xDEADFACE);
            println!("instruction not applied");
            Ok(())
        };

        machine
            .proc
            .code_hook(0x4000, 0x4000, Box::new(code_cb))
            .unwrap();

        println!("running");
        machine.run();

        let r1_value = machine.proc.read_register::<u32>(ArmRegister::R1).unwrap();
        // Check instruction has been applied
        assert_eq!(r1_value, 0xCAFEBABE);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_write_memory_hook_execution_order() {
        // Ensures that memory write hooks are triggered BEFORE memory is written
        // Also ensures memory write parameters are correct
        let mut machine = TestMachine::with_code("str r0, [r1]");

        machine
            .proc
            .write_register(ArmRegister::R0, 0xCAFEBABEu32)
            .unwrap();
        machine
            .proc
            .write_register(ArmRegister::R1, 0x4040u32)
            .unwrap();
        machine
            .mmu
            .data()
            .write(0x4040)
            .le()
            .value(0xDEADFACEu32)
            .unwrap();

        let mem_write_cb = |cpu: CoreHandle, address: u64, size: u32, write_value: &[u8]| {
            let memory_value = cpu.mmu.data().read(0x4040).le().u32().unwrap();
            // Check instruction is not applied
            assert_eq!(memory_value, 0xDEADFACE);
            // Check written value is correct
            assert_eq!(&write_value[0..size as usize], &0xCAFEBABEu32.to_le_bytes());
            assert_eq!(address, 0x4040);
            Ok(())
        };

        machine
            .proc
            .mem_write_hook(0x4040, 0x4040, Box::new(mem_write_cb))
            .unwrap();

        machine.run();

        let memory_value = machine.mmu.data().read(0x4040).le().u32().unwrap();

        // Check instruction has been applied
        assert_eq!(memory_value, 0xCAFEBABE);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_out_of_band_mem_access() {
        // Ensures that memory write hooks are triggered BEFORE memory is written
        // Also ensures memory write parameters are correct
        let mut machine = TestMachine::with_code("str r0, [r1]");
        const TEST_ADDR: u64 = 0x4040;

        machine
            .proc
            .write_register(ArmRegister::R0, 0xCAFEBABEu32)
            .unwrap();
        machine
            .proc
            .write_register(ArmRegister::R1, TEST_ADDR as u32)
            .unwrap();
        machine
            .mmu
            .data()
            .write(TEST_ADDR)
            .le()
            .value(0xDEADFACEu32)
            .unwrap();

        // Get the region that corresponds to the memory we are accessing.
        let region = machine
            .mmu
            .regions()
            .unwrap()
            .find(|r| r.contains_region((0x4000, 0x1000)))
            .unwrap();

        // Verify that the value we read directly from the region matches what we wrote through the
        // backend.
        let region_read_val = region.read(TEST_ADDR).le().u32().unwrap();
        assert_eq!(region_read_val, 0xDEADFACE);

        machine.run();

        let mut region = machine
            .mmu
            .regions()
            .unwrap()
            .find(|r| r.contains_region((0x4000, 0x1000)))
            .unwrap();
        // Verify that the value we read directly from the region matches the changes made by the
        // emulated instruction.
        let region_read_val = region.read(TEST_ADDR).le().u32().unwrap();
        assert_eq!(region_read_val, 0xCAFEBABE);

        // Write data directly to the region and verify that the backend read reflects this change.
        region.write(TEST_ADDR).le().value(0x00FACADEu32).unwrap();

        let unicorn_read_val = u32::from_le_bytes(
            machine
                .proc
                .inner()
                .mem_read_as_vec(TEST_ADDR, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert_eq!(unicorn_read_val, 0x00FACADE);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_read_memory_hook_execution_order() {
        // Ensures that memory read hooks are triggered BEFORE read instruction executes
        // Also ensures memory read callback parameters are correct
        let mut machine = TestMachine::with_code("ldr r0, [r1]");

        machine
            .proc
            .write_register(ArmRegister::R0, 0xCAFEBABEu32)
            .unwrap();
        machine
            .proc
            .write_register(ArmRegister::R1, 0x4040u32)
            .unwrap();
        machine
            .mmu
            .data()
            .write(0x4040)
            .le()
            .value(0xDEADFACEu32)
            .unwrap();

        let mem_read_cb = |proc: CoreHandle, address: u64, size: u32, read_value: &mut [u8]| {
            let register_value = proc.cpu.read_register::<u32>(ArmRegister::R0).unwrap();
            // Check instruction is not applied
            assert_eq!(register_value, 0xCAFEBABE);
            // Check read value is correct
            assert_eq!(&read_value[0..size as usize], &0xDEADFACEu32.to_le_bytes());
            assert_eq!(address, 0x4040);
            Ok(())
        };

        machine
            .proc
            .add_hook(StyxHook::memory_read(0x4040..=0x4040, mem_read_cb))
            .unwrap();

        machine.run();

        let register_value = machine.proc.read_register::<u32>(ArmRegister::R0).unwrap();
        // Check instruction has been applied
        assert_eq!(register_value, 0xDEADFACE);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_read_memory_hook_modify() {
        // Ensures that memory read hooks can modify their read data
        let mut machine = TestMachine::with_code("ldr r0, [r1]");

        machine
            .proc
            .write_register(ArmRegister::R0, 0xCAFEBABEu32)
            .unwrap();
        machine
            .proc
            .write_register(ArmRegister::R1, 0x4040u32)
            .unwrap();
        machine
            .mmu
            .data()
            .write(0x4040)
            .le()
            .value(0xDEADFACEu32)
            .unwrap();

        let mem_read_cb = |proc: CoreHandle, address: u64, size: u32, read_value: &mut [u8]| {
            let register_value = proc.cpu.read_register::<u32>(ArmRegister::R0).unwrap();
            // Check instruction is not applied
            assert_eq!(register_value, 0xCAFEBABE);
            // Check read value is correct
            assert_eq!(&read_value[0..size as usize], &0xDEADFACEu32.to_le_bytes());
            assert_eq!(address, 0x4040);

            let facebeef = 0xFACEBEEFu32.to_le_bytes();
            read_value.copy_from_slice(&facebeef);
            Ok(())
        };

        machine
            .proc
            .add_hook(StyxHook::memory_read(0x4040..=0x4040, mem_read_cb))
            .unwrap();

        machine.run();

        let register_value = machine.proc.read_register::<u32>(ArmRegister::R0).unwrap();
        // Check changed data has been applied
        assert_eq!(register_value, 0xFACEBEEF);
    }
}
