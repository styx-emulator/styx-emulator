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
use std::{borrow::Cow, ffi::CStr};

#[derive(Copy, Clone, Debug)]
#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct cstring(*const std::ffi::c_char);

crate::macros::newtype_from!(*const std::ffi::c_char as cstring);

impl cstring {
    pub fn to_cstr(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.0) }
    }

    pub fn to_str(&self) -> Result<&str, std::str::Utf8Error> {
        self.to_cstr().to_str()
    }
}

impl From<cstring> for String {
    fn from(this: cstring) -> String {
        let str = this.to_str().expect("invalid utf8 string passed!");
        str.to_string()
    }
}

#[derive(Copy, Clone, Debug)]
#[allow(non_camel_case_types)]
pub struct c_uint8_array<'a>(&'a *const u8, usize);

impl<'a, T> From<(&'a *const u8, T)> for c_uint8_array<'a>
where
    T: TryInto<usize, Error: std::fmt::Debug>,
{
    fn from((bytes, len): (&'a *const u8, T)) -> Self {
        let len = len.try_into().unwrap();
        Self(bytes, len)
    }
}

impl<'a> c_uint8_array<'a> {
    pub fn as_slice(&self) -> &'a [u8] {
        unsafe { std::slice::from_raw_parts(*self.0, self.1) }
    }
}

impl<'a> From<c_uint8_array<'a>> for &'a [u8] {
    fn from(value: c_uint8_array<'a>) -> Self {
        value.as_slice()
    }
}

impl<'a> From<c_uint8_array<'a>> for Cow<'a, [u8]> {
    fn from(value: c_uint8_array<'a>) -> Self {
        Cow::Borrowed(value.as_slice())
    }
}

impl From<c_uint8_array<'_>> for Vec<u8> {
    fn from(value: c_uint8_array<'_>) -> Self {
        value.as_slice().to_vec()
    }
}

#[derive(Copy, Clone, Debug)]
#[allow(non_camel_case_types)]
pub struct c_uint8_array_mut<'a>(&'a *mut u8, usize);

impl<'a, T> From<(&'a *mut u8, T)> for c_uint8_array_mut<'a>
where
    T: TryInto<usize, Error: std::fmt::Debug>,
{
    fn from((bytes, len): (&'a *mut u8, T)) -> Self {
        let len = len.try_into().unwrap();
        Self(bytes, len)
    }
}

impl<'a> c_uint8_array_mut<'a> {
    pub fn as_slice(&self) -> &'a [u8] {
        unsafe { std::slice::from_raw_parts(*self.0, self.1) }
    }

    pub fn as_mut_slice(&self) -> &'a mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(*self.0, self.1) }
    }
}

impl<'a> From<c_uint8_array_mut<'a>> for &'a [u8] {
    fn from(value: c_uint8_array_mut<'a>) -> Self {
        value.as_slice()
    }
}

impl<'a> From<c_uint8_array_mut<'a>> for &'a mut [u8] {
    fn from(value: c_uint8_array_mut<'a>) -> Self {
        value.as_mut_slice()
    }
}

impl<'a> From<c_uint8_array_mut<'a>> for Cow<'a, [u8]> {
    fn from(value: c_uint8_array_mut<'a>) -> Self {
        Cow::Borrowed(value.as_slice())
    }
}

impl From<c_uint8_array_mut<'_>> for Vec<u8> {
    fn from(value: c_uint8_array_mut<'_>) -> Self {
        value.as_slice().to_vec()
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
#[allow(non_camel_case_types)]
pub struct cbytes(*const u8);
crate::macros::newtype_from!(*const u8 as cbytes);

impl From<&mut [u8]> for cbytes {
    fn from(value: &mut [u8]) -> Self {
        Self(value.as_ptr())
    }
}

impl From<&[u8]> for cbytes {
    fn from(value: &[u8]) -> Self {
        Self(value.as_ptr())
    }
}

#[allow(dead_code)]
impl cbytes {
    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }

    pub unsafe fn as_slice(&self, len: usize) -> &'static [u8] {
        unsafe { std::slice::from_raw_parts(self.0, len) }
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
#[allow(non_camel_case_types)]
pub struct cbytes_mut(*mut u8);
crate::macros::newtype_from!(*mut u8 as cbytes_mut);

impl From<&mut [u8]> for cbytes_mut {
    fn from(value: &mut [u8]) -> Self {
        Self(value.as_mut_ptr())
    }
}

#[allow(dead_code)]
impl cbytes_mut {
    pub unsafe fn as_slice(&self, len: usize) -> &'static [u8] {
        unsafe { std::slice::from_raw_parts(self.0, len) }
    }

    pub unsafe fn as_mut_slice(&self, len: usize) -> &'static mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.0, len) }
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
#[allow(non_camel_case_types)]
pub struct cbool(i32);

crate::macros::newtype_from!(i32 as cbool);

impl From<cbool> for bool {
    fn from(cbool(value): cbool) -> Self {
        value != 0
    }
}

impl From<cbool> for () {
    fn from(_: cbool) -> Self {
        ()
    }
}
