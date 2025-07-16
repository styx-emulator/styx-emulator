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
//! unsafe utilities to reduce unsafe code duplication

/// Convert any `Sized` struct to a u8 slice
///
/// # Safety
/// Any struct that uses this *must* be `#[repr(C)]` or `#[repr(transparent)]`
/// in order to guarantee consistent sizing and avoid undefined behavior
///
/// # Source
/// <https://stackoverflow.com/a/42186553>, except converted to a `const fn`
/// ```rust
/// use styx_util::unsafe_lib::any_as_u8_slice;
///
/// #[repr(C)]
/// #[derive(Default)]
/// struct MyStruct {
///     a_field: u32, // +4 bytes of padding
///     another_field: u64,
/// }
///
/// let my_instance = MyStruct::default();
/// assert_eq!(16, unsafe { any_as_u8_slice(&my_instance).len() });
/// ```
pub const unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe {
        ::core::slice::from_raw_parts((p as *const T) as *const u8, ::core::mem::size_of::<T>())
    }
}

/// Convert any mut `Sized` struct to a mut u8 slice
///
/// # Safety
/// Any struct that uses this *must* be `#[repr(C)]` or `#[repr(transparent)]`
/// in order to guarantee consistent sizing and avoid undefined behavior
///
/// # const
/// This function cannot be const until <https://github.com/rust-lang/rust/issues/67456>
/// is merged
///
/// # Source
/// <https://stackoverflow.com/a/42186553>, except converted to a `const fn`
/// ```rust
/// use styx_util::unsafe_lib::any_as_u8_slice_mut;
///
/// #[repr(C)]
/// #[derive(Default)]
/// struct MyStruct {
///     a_field: u32, // +4 bytes of padding
///     another_field: u64,
/// }
///
/// let mut my_instance = MyStruct::default();
/// assert_eq!(16, unsafe { any_as_u8_slice_mut(&mut my_instance).len() });
/// ```
pub unsafe fn any_as_u8_slice_mut<T: Sized>(p: &mut T) -> &mut [u8] {
    unsafe {
        ::core::slice::from_raw_parts_mut((p as *mut T) as *mut u8, ::core::mem::size_of::<T>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    #[derive(Default)]
    struct Size16 {
        offset_0: u32, // +4 padding
        offset_8: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct Size2 {
        offset_0: u8,
        offset_1: u8,
    }

    #[repr(C)]
    #[derive(Default)]
    struct Size24 {
        offset_0: u8, // +1 padding
        offset_2: u16,
        offset_4: u16, // +2 padding
        offset_8: u32, // +4 padding
        offset_16: u64,
    }

    #[test]
    fn test_any_as_u8_slice() {
        let size_16 = Size16::default();
        let size_2 = Size2::default();
        let size_24 = Size24::default();

        assert_eq!(16, unsafe { any_as_u8_slice(&size_16).len() });
        assert_eq!(2, unsafe { any_as_u8_slice(&size_2).len() });
        assert_eq!(24, unsafe { any_as_u8_slice(&size_24).len() });
    }

    #[test]
    fn test_any_as_u8_slice_mut() {
        let mut size_16 = Size16::default();
        let mut size_2 = Size2::default();
        let mut size_24 = Size24::default();

        let size_16_mut = unsafe { any_as_u8_slice_mut(&mut size_16) };
        let size_2_mut = unsafe { any_as_u8_slice_mut(&mut size_2) };
        let size_24_mut = unsafe { any_as_u8_slice_mut(&mut size_24) };

        assert_eq!(16, size_16_mut.len());
        assert_eq!(2, size_2_mut.len());
        assert_eq!(24, size_24_mut.len());

        size_16_mut[0] = 0xf;
        size_2_mut[0] = 0xf;
        size_24_mut[0] = 0xf;

        assert_eq!(0xf, size_16.offset_0);
        assert_eq!(0xf, size_2.offset_0);
        assert_eq!(0xf, size_24.offset_0);
    }
}
