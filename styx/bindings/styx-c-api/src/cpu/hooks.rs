// SPDX-License-Identifier: BSD-2-Clause
crate::data::opaque_pointer! {
    /// A processor-specific unique identifier of an added hook
    pub struct StyxHookToken(styx_emulator::hooks::HookToken)
}

/// free the hook token's handle
#[no_mangle]
pub extern "C" fn StyxHookToken_free(ptr: *mut StyxHookToken) {
    StyxHookToken::free(ptr)
}

/// this looks scary, but it's not that bad!
///
/// this macro calls another macro with each variant of a code hook.
///     - NOTE: data hooks are not included, the only difference is that they have a `userdata:
///         Arc<dyn Any>` field though
///
/// # Example
/// ```rust
/// macro_rules! {
///     (
///         $name:ident( $($an:ident: $at:ty),* $(,)? ) $(-> $rt:ty)? $({
///             $($pn:ident: $pt:ty),* $(,)?
///         })?
///         ;
///     ) => {
///         // do what you want here!
///     }
/// }
/// ```
macro_rules! hook_xmacro {
    ($x:ident $($t:tt)*) => {
        $x! {
            Code() -> (): () {
                start: u64,
                end: u64,
            };
            $($t)*
        }
        $x! {
            Block(addr: u64: u64, size: u32: u32) -> (): ();
            $($t)*
        }
        $x! {
            MemoryWrite(addr: u64: u64, size: u32: u32, data: $crate::data::ArrayPtr<u8>: &[u8]) -> (): () {
                start: u64,
                end: u64,
            };
            $($t)*
        }
        $x! {
            MemoryRead(addr: u64: u64, size: u32: u32, data: $crate::data::ArrayPtrMut<u8>: &mut [u8]) -> (): () {
                start: u64,
                end: u64,
            };
            $($t)*
        }
        $x! {
            Interrupt(intno: i32: i32) -> (): ();
            $($t)*
        }
        $x! {
            InvalidInstruction() -> $crate::data::CBool: styx_emulator::hooks::Resolution;
            $($t)*
        }
        $x! {
            ProtectionFault(addr: u64: u64, size: u32: u32, region_perms: $crate::cpu::MemoryPermissions: styx_emulator::prelude::MemoryPermissions, fault_data: $crate::cpu::MemFaultData: styx_emulator::hooks::MemFaultData) -> $crate::data::CBool: styx_emulator::hooks::Resolution {
                start: u64,
                end: u64,
            };
            $($t)*
        }
        $x! {
            UnmappedFault(addr: u64: u64, size: u32: u32, fault_data: $crate::cpu::MemFaultData: styx_emulator::hooks::MemFaultData) -> $crate::data::CBool: styx_emulator::hooks::Resolution {
                start: u64,
                end: u64,
            };
            $($t)*
        }
    }
}
pub(crate) use hook_xmacro;
use styx_emulator::hooks::{AddressRange, CoreHandle};

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
#[allow(non_camel_case_types)]
pub struct StyxHookUserData(*mut core::ffi::c_void);
unsafe impl Send for StyxHookUserData {}
unsafe impl Sync for StyxHookUserData {}

pub fn get_range(start: u64, end: u64) -> AddressRange {
    (start..=end).into()
}

// is this horrible
// hack to extend CoreHandle lifetime
fn lifetime_expand(handle: CoreHandle<'_>) -> CoreHandle<'static> {
    unsafe { std::mem::transmute(handle) }
}

macro_rules! define_hooks {
    (
        $name:ident( $($an:ident: $at:ty: $att:ty),* $(,)? ) $(-> $rt:ty: $rtt:ty)? $({
            $($pn:ident: $pt:ty),* $(,)?
        })?
        ;
    ) => {
        paste::paste! {
            #[allow(non_camel_case_types)]
            pub type [< StyxHook_ $name Callback >] = unsafe extern "C" fn(cpu: $crate::cpu::StyxProcessorCore, $($an: $at),*) $(-> $rt)?;

            #[repr(C)]
            #[allow(non_camel_case_types)]
            pub struct [< StyxHook_ $name >] {
                $( $($pn: $pt,)* )?
                callback: [< StyxHook_ $name Callback >],
            }

            impl styx_emulator::hooks::[< $name Hook >] for [< StyxHook_ $name >] {
                fn call(&mut self, proc: styx_emulator::hooks::CoreHandle, $($an: $att,)*) -> Result<$($rtt)?, styx_emulator::prelude::UnknownError>{
                   unsafe {
                        let processor_core = $crate::cpu::StyxProcessorCore::new(lifetime_expand(proc)).unwrap();
                        Ok((self.callback)(processor_core, $($an.into()),*).into())
                    }
                }
            }

            impl From<[< StyxHook_ $name >]> for styx_emulator::hooks::StyxHook {
                fn from(hook: [< StyxHook_ $name >]) -> Self {
                    Self::$name (
                        $( get_range($( hook.$pn,)*), )?
                        Box::new(hook)
                    )
                }
            }

            #[allow(non_camel_case_types)]
            pub type [< StyxHook_ $name DataCallback >] = unsafe extern "C" fn($crate::cpu::StyxProcessorCore, $($an: $at,)* StyxHookUserData) $(-> $rt)?;

            #[repr(C)]
            #[allow(non_camel_case_types)]
            pub struct [< StyxHook_ $name Data >] {
                $( $($pn: $pt,)* )?
                callback: [< StyxHook_ $name DataCallback >],
                userdata: StyxHookUserData,
            }

            impl styx_emulator::hooks::[< $name Hook >] for [< StyxHook_ $name Data >] {
                fn call(&mut self, proc: styx_emulator::hooks::CoreHandle, $($an: $att,)*) -> Result<$($rtt)?, styx_emulator::prelude::UnknownError>{
                    unsafe {
                        let processor_core = $crate::cpu::StyxProcessorCore::new(lifetime_expand(proc)).unwrap();
                        Ok((self.callback)(processor_core, $($an.into(),)* self.userdata).into())
                    }
                }
            }

            impl From<[< StyxHook_ $name Data >]> for styx_emulator::hooks::StyxHook {
                fn from(hook: [< StyxHook_ $name Data >]) -> Self {
                    Self::$name (
                        $( get_range($( hook.$pn,)*), )?
                        Box::new(hook)
                    )
                }
            }
        }
    };
}

hook_xmacro!(define_hooks);
