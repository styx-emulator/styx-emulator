// SPDX-License-Identifier: BSD-2-Clause
use std::{
    convert::Infallible,
    num::TryFromIntError,
    ops::{ControlFlow, FromResidual, Try},
    ptr::NonNull,
};

use styx_emulator::core::hooks::AddHookError;
use styx_emulator::prelude::{MmuOpError, ReadRegisterError, UnknownError, WriteRegisterError};

macro_rules! styx_ffi_error_impl {
    (
        $(#[$($attr:tt)*])*
        pub struct $sname:ident(
            $(#[$($eattr:tt)*])*
            enum {
                $(
                    $(#[$($tattr:tt)*])*
                    $tname:ident(
                        $(#[$($vattr:tt)*])*
                        struct {
                            $(
                                $(#[$($fattr:tt)*])*
                                $fname:ident: $ty:ty
                            ),* $(,)?
                        }
                    )
                ),* $(,)?
            }
        )
    ) => {
        ::paste::paste! {
            $(#[$($attr)*])*
            #[repr(C)]
            pub struct $sname {
                pub kind: [< $sname Kind >],
                pub data: *mut ::core::ffi::c_void,
            }

            impl std::fmt::Debug for $sname {
                fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    match self.kind {
                        $( [< $sname Kind >]::$tname => {
                            let ptr: *mut [< $sname _ $tname >] = self.data as *mut [< $sname _ $tname >];
                            if let Some(value) = (ptr.is_aligned().then(|| unsafe { ptr.as_ref() }).and_then(|v| v)) {
                                std::fmt::Debug::fmt(value, f)
                            } else {
                                f
                                    .debug_tuple(concat!(stringify!($sname), "::", stringify!($tname)))
                                    .field(&format_args!("INVALID/NULL POINTER: {:?}", ptr))
                                    .finish()
                            }
                        })*
                        #[allow(unreachable_patterns)]
                        _ => {
                            f
                                .debug_tuple(concat!(stringify!($sname), "::???"))
                                .field(&format_args!("INVALID ERROR KIND"))
                                .finish()
                        },
                    }
                }
            }

            #[repr(C)]
            #[allow(non_camel_case_types)]
            #[non_exhaustive]
            $(#[$($eattr)*])*
            pub enum [< $sname Kind >] {
                $( $(#[$($tattr)*])* $tname ),*
            }

            #[allow(non_camel_case_types)]
            pub type [< $sname Msg_t >] = *mut core::ffi::c_char;

            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn [< $sname Msg >](error: $sname) -> [< $sname Msg_t >] { unsafe {
                if error.data.is_null() {
                    eprintln!("invalid error supplied!");
                    return std::ptr::null_mut();
                }

                let msg: String = match error.kind {
                    $(
                        [< $sname Kind >]::$tname => {
                            let ptr: *mut [< $sname _ $tname >] = error.data as *mut [< $sname _ $tname >];
                            let Some(value) = (unsafe { ptr.as_ref() }) else {
                                eprintln!("invalid error supplied!");
                                return std::ptr::null_mut();
                            };
                            ToString::to_string(value)
                        }
                    )*
                    #[allow(unreachable_patterns)]
                    _ => {
                        eprintln!("invalid error supplied!");
                        return std::ptr::null_mut();
                    },
                };
                let cmsg = match std::ffi::CString::new(msg) {
                    Ok(msg) => msg,
                    Err(e) => {
                        eprintln!("The error message could not be converted to a c-string, so I printed it instead: {e}");
                        return std::ptr::null_mut();
                    }
                };

                let msg_len = cmsg.as_bytes_with_nul().len();
                let layout = match std::alloc::Layout::array::< [< $sname Msg_t >] >(msg_len)  {
                    Ok(layout) => layout,
                    Err(e) => {
                        let msg = String::from_utf8(cmsg.into_bytes()).expect("return to string");
                        eprintln!("ERROR:\n{msg}\n\nunable to allocate error message buffer: {e}");
                        return std::ptr::null_mut();
                    }
                };

                let out_ptr = std::alloc::alloc(layout) as [< $sname Msg_t >];
                if out_ptr.is_null() {
                    let msg = String::from_utf8(cmsg.into_bytes()).expect("return to string");
                    eprintln!("ERROR:\n{msg}\n\nunable to allocate error message buffer");
                    return std::ptr::null_mut();
                }
                std::ptr::copy_nonoverlapping(cmsg.as_ptr(), out_ptr, msg_len);
                out_ptr
            }}

            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn [< $sname Msg_free >](msg: [< $sname Msg_t >]) { unsafe {
                let cstr = core::ffi::CStr::from_ptr(msg);
                let len = cstr.count_bytes() + 1;
                let layout = match std::alloc::Layout::array::<[< $sname Msg_t >]>(len) {
                    Ok(layout) => layout,
                    Err(e) => {
                        eprintln!("unable to deallocate message, this will case a memory leak: {e}");
                        return;
                    }
                };
                std::alloc::dealloc(msg as *mut u8, layout);
            }}

            $(
                #[derive(Debug)]
                #[allow(non_camel_case_types)]
                $(#[$($vattr)*])*
                pub struct [< $sname _ $tname >] {
                    $( $(#[$($fattr)*])* $fname: $ty),*
                }

                impl std::fmt::Display for [< $sname _ $tname >] {
                    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                        f.debug_struct(stringify!($tname))
                            $( .field(stringify!(), &format_args!("{}", self.$fname)) )*
                            .finish()
                    }
                }

                impl From<[< $sname _ $tname >]> for $sname {
                    fn from([< $sname _ $tname >]{ $($fname),* }: [< $sname _ $tname >]) -> Self {
                        Self::[< $tname:snake >]($($fname),*)
                    }
                }

                impl $sname {
                    pub(crate) fn [< $tname:snake >](
                        $($fname: $ty),*
                    ) -> Self {
                        let layout = std::alloc::Layout::new::<[< $sname _ $tname >]>();
                        let ptr = unsafe {
                            let out = std::alloc::alloc(layout) as *mut [< $sname _ $tname >];
                            std::ptr::write(out, [< $sname _ $tname >] { $($fname),* });
                            out
                        };

                        Self {
                            kind: [< $sname Kind >]::$tname,
                            data: ptr as *mut core::ffi::c_void,
                        }
                    }
                }
            )*
        }
    };
}

// FYI, you can add annotations to any of these itmes, (above the enum keyword, or any struct
// keyword, or any struct field!)
styx_ffi_error_impl! {
    #[repr(C)]
    pub struct StyxFFIError(
        #[derive(Debug)]
        enum {
            NullOutput(
                struct {}
            ),
            NullInput(
                struct {}
            ),
            NullArray(
                struct {}
            ),
            NullString(
                struct {}
            ),
            AllocationError(
                struct {}
            ),
            InvalidArrayLength(
                struct {
                    inner: Box<dyn std::error::Error>,
                }
            ),
            InvalidStringLength(
                struct {
                    inner: Box<dyn std::error::Error>,
                }
            ),
            InvalidString(
                struct {
                    inner: std::str::Utf8Error,
                }
            ),
            AddHook(
                struct {
                    inner: AddHookError
                }
            ),
            MmuOp(
                struct {
                    inner: MmuOpError
                }
            ),
            ReadRegister(
                struct {
                    inner: ReadRegisterError
                }
            ),
            WriteRegister(
                struct {
                    inner: WriteRegisterError
                }
            ),
            TryFromInt(
                struct {
                    inner: TryFromIntError,
                }
            ),
            TryNewArbitraryInt(
                struct {
                    inner: styx_emulator::prelude::TryNewIntError,
                }
            ),
            Unknown(
                struct {
                    inner: UnknownError
                }
            ),
        }
    )
}

#[repr(transparent)]
pub struct StyxFFIErrorPtr(*mut StyxFFIError);

impl StyxFFIErrorPtr {
    #[allow(non_upper_case_globals)]
    pub const Ok: StyxFFIErrorPtr = StyxFFIErrorPtr(core::ptr::null_mut());

    pub fn err(error: impl Into<StyxFFIError>) -> Self {
        Self::from(error.into())
    }
}

impl From<StyxFFIError> for StyxFFIErrorPtr {
    fn from(value: StyxFFIError) -> Self {
        let layout = std::alloc::Layout::new::<StyxFFIError>();
        unsafe {
            let ptr = std::alloc::alloc(layout) as *mut StyxFFIError;
            std::ptr::write(ptr, value);
            Self(ptr)
        }
    }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "C" fn StyxFFIErrorPtr_free(result: *mut StyxFFIErrorPtr) {
    let Some(outer) = (unsafe { result.as_mut() }) else {
        return;
    };
    let Some(inner) = NonNull::new(outer.0) else {
        return;
    };
    unsafe {
        std::ptr::drop_in_place::<StyxFFIError>(inner.as_ptr());
        std::ptr::write::<StyxFFIErrorPtr>(result, StyxFFIErrorPtr::Ok);
    }
}

impl Try for StyxFFIErrorPtr {
    type Output = ();
    type Residual = StyxFFIErrorPtr;

    #[inline]
    fn from_output(_: Self::Output) -> Self {
        StyxFFIErrorPtr(std::ptr::null_mut())
    }

    fn branch(self) -> std::ops::ControlFlow<Self::Residual, Self::Output> {
        if self.0.is_null() {
            ControlFlow::Continue(())
        } else {
            ControlFlow::Break(self)
        }
    }
}

impl FromResidual<StyxFFIErrorPtr> for StyxFFIErrorPtr {
    #[inline]
    fn from_residual(residual: StyxFFIErrorPtr) -> Self {
        residual
    }
}

impl<E: Into<StyxFFIError>> FromResidual<Result<Infallible, E>> for StyxFFIErrorPtr {
    #[inline]
    fn from_residual(residual: Result<Infallible, E>) -> Self {
        match residual {
            Ok(_) => unreachable!(),
            Err(e) => {
                let layout = std::alloc::Layout::new::<StyxFFIError>();
                unsafe {
                    let ptr = std::alloc::alloc(layout) as *mut StyxFFIError;
                    std::ptr::write(ptr, e.into());
                    StyxFFIErrorPtr(ptr)
                }
            }
        }
    }
}

macro_rules! from_error_impl {
    (impl From<$t:ty as $n:ident>) => {
        impl From<$t> for StyxFFIError {
            #[inline]
            fn from(value: $t) -> Self {
                Self::$n(value)
            }
        }
    };
}

from_error_impl!(impl From<TryFromIntError as try_from_int>);
from_error_impl!(impl From<styx_emulator::prelude::TryNewIntError as try_new_arbitrary_int>);
from_error_impl!(impl From<UnknownError as unknown>);
from_error_impl!(impl From<AddHookError as add_hook>);
from_error_impl!(impl From<MmuOpError as mmu_op>);
from_error_impl!(impl From<ReadRegisterError as read_register>);
from_error_impl!(impl From<WriteRegisterError as write_register>);
