// SPDX-License-Identifier: BSD-2-Clause
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
                pub unsafe fn from_mut(value: &mut $t) -> Self { unsafe {
                    let out = $crate::data::OpaquePointer::from_mut(value);
                    Self(out)
                }}
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
