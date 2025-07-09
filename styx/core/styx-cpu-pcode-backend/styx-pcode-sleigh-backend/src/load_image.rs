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
use styx_sleigh_bindings::{ffi, LoadImage, RustLoadImage};

use crate::sleigh_obj::{DeriveParent, SleighObj};

pub struct RustLoadImageProxy<L> {
    pub obj: SleighObj<ffi::RustLoadImageProxy>,
    pub _loader: Box<L>,
    rust_loader_ptr: *mut RustLoadImage<'static>,
}

// I think this is good?
// unsafe impl Send for RustLoadImageProxy {}
// unsafe impl Sync for RustLoadImageProxy {}

impl<L: LoadImage + 'static> RustLoadImageProxy<L> {
    pub fn new(loader: L) -> Self {
        // Move loader to the heap
        let mut loader = Box::new(loader);

        // magic
        let rust_loader = unsafe {
            Box::new(RustLoadImage::from_internal(std::mem::transmute::<
                &mut L,
                &'static mut L,
            >(loader.as_mut())))
        };

        // rust_loader_ptr holds a reference to `loader` inside self
        // To avoid something self referential we leak the pointer and
        // promise to free it later.
        let rust_loader_ptr: *mut RustLoadImage<'static> = Box::leak(rust_loader);

        // newRustLoadImageProxy will never create a null ptr
        let obj =
            SleighObj::from_unique_ptr(unsafe { ffi::newRustLoadImageProxy(rust_loader_ptr) })
                .unwrap();

        Self {
            obj,
            _loader: loader,
            rust_loader_ptr,
        }
    }
}

// Safe because RustLoadImageProxy does indeed derive from LoadImage
unsafe impl DeriveParent<ffi::LoadImage> for SleighObj<ffi::RustLoadImageProxy> {}

impl<L> Drop for RustLoadImageProxy<L> {
    fn drop(&mut self) {
        // Free the rust loader
        drop(unsafe { Box::from_raw(self.rust_loader_ptr) });
    }
}

struct SliceLoader<'a> {
    start: u64,
    data: &'a [u8],
}

impl Loader for SliceLoader<'_> {
    fn load(&mut self, ptr: &mut [u8], address: u64) {
        ptr.fill(0);

        if self.start <= address {
            let len = self.data.len();
            let required = ptr.len();
            let offset = (address - self.start) as usize;
            let fill_len = required.min(len - offset);
            let data = self.data.get(offset..offset + fill_len);
            match data {
                Some(data_slice) => ptr[..fill_len].copy_from_slice(data_slice),
                None => panic!(
                    "Attempted out of bounds read at 0x{:X}-0x{:X} (start = 0x{:X}, slice_len = {})",
                    offset,
                    offset + fill_len,
                    self.start,
                    self.data.len()
                ),
            }
        } else {
            println!("Req address less than start")
        }
    }
}

/// [Loader] from an owned [Vec] of data.
pub struct VectorLoader {
    /// Data vec starts at this address.
    pub start: u64,
    /// Data that will be loaded, indexed at `start`.
    pub data: Vec<u8>,
}

impl Loader for VectorLoader {
    fn load(&mut self, ptr: &mut [u8], address: u64) {
        let mut s = SliceLoader {
            start: self.start,
            data: &self.data,
        };
        s.load(ptr, address);
    }
}

impl LoaderRequires for VectorLoader {
    type LoadRequires<'a> = ();

    fn set_data(&mut self, _data: Self::LoadRequires<'_>) {}
}

/// Needed to implement [styx_sleigh_bindings::LoadImage] for all [Loader]s.
pub struct LoaderWrapper<L>(pub L);

/// Used to provide code bytes to the Sleigh.
///
/// Implementora also implement [styx_sleigh_bindings::LoadImage] using
/// [LoaderWrapper]. This is to avoid [crate::Sleigh] users needing to use the ffi api.
pub trait Loader {
    fn load(&mut self, ptr: &mut [u8], address: u64);
}

impl<L: Loader> styx_sleigh_bindings::LoadImage for LoaderWrapper<L> {
    fn load_fill(&mut self, ptr: &mut [u8], address: &ffi::Address) {
        let address_offset = address.getOffset();
        self.0.load(ptr, address_offset)
    }
}

impl<L: LoaderRequires> LoaderRequires for LoaderWrapper<L> {
    type LoadRequires<'a> = L::LoadRequires<'a>;

    fn set_data(&mut self, data: Self::LoadRequires<'_>) {
        self.0.set_data(data);
    }
}

pub trait LoaderRequires {
    type LoadRequires<'a>;

    fn set_data(&mut self, data: Self::LoadRequires<'_>);
}
