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
macro_rules! opaque_pointer {
    (
        $(#[doc $($doc:tt)+])*
        pub struct $n:ident($t:ty)
    ) => {
        ::paste::paste! {
            $(#[doc $($doc)+])*
            #[repr(C)]
            #[allow(non_camel_case_types)]
            pub struct [< $n _t >];
            impl $crate::data::OpaquePointerType for [< $n _t >] {
                type To = $t;
            }

            #[allow(non_camel_case_types)]
            #[repr(transparent)]
            pub struct $n($crate::data::OpaquePointer<[< $n _t >]>);

            impl $n {
                pub fn new(value: $t) -> Result<Self, $crate::data::StyxFFIError> {
                    Ok(Self($crate::data::OpaquePointer::new(value)?))
                }

                pub fn free(value: *mut Self) {
                    $crate::data::OpaquePointer::free(value.cast::<$crate::data::OpaquePointer<[< $n _t >]>>())
                }

                /// create an opaque pointer from a mutable reference
                ///
                /// # Safety
                /// ensure that this pointer is not free'd and that the mutable reference outlives
                /// the lifetime of this pointer
                pub unsafe fn from_mut(value: &mut $t) -> Self {
                    let out = $crate::data::OpaquePointer::from_mut(value);
                    Self(out)
                }
            }

            impl std::ops::Deref for $n {
                type Target = $crate::data::OpaquePointer<[< $n _t >]>;

                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }

            impl std::ops::DerefMut for $n {
                fn deref_mut(&mut self) -> &mut $crate::data::OpaquePointer<[< $n _t >]> {
                    &mut self.0
                }
            }

            impl From<$n> for $crate::data::OpaquePointer<[< $n _t >]> {
                fn from($n(value): $n) -> Self {
                    value
                }
            }
        }
    };
}
pub(crate) use opaque_pointer;
