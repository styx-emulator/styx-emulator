// SPDX-License-Identifier: BSD-2-Clause
use styx_sleigh_bindings::{ffi, LoadImage, RustLoadImage};

use crate::sleigh_obj::{DeriveParent, SleighObj};

pub struct RustLoadImageProxy<L> {
    /// The byte loader.
    ///
    /// We must keep this valid and at the same position in memory while RustLoadImage and the Rust LoadImageProxy exist.
    pub(crate) loader: Box<L>,

    /// Leaked Box of RustLoadImage.
    ///
    /// Contains an alias to `loader`.
    rust_loader_ptr: *mut RustLoadImage<'static>,

    /// Aliased to `rust_loader_ptr`
    pub obj: SleighObj<ffi::RustLoadImageProxy>,
}

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
            loader,
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
    type LoadRequires<'a> = ();
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
    type LoadRequires<'a> = ();
    fn load(&mut self, ptr: &mut [u8], address: u64) {
        let mut s = SliceLoader {
            start: self.start,
            data: &self.data,
        };
        s.load(ptr, address);
    }
}

/// Needed to implement [styx_sleigh_bindings::LoadImage] for all [Loader]s.
pub struct LoaderWrapper<L>(pub L);

impl<L: Loader> LoaderWrapper<L> {
    /// Set the Loader data before doing a load
    ///
    /// # Safety
    ///
    /// The caller must ensure that the mutable reference on `data` is kept through the load.
    pub unsafe fn set_data(&mut self, data: &mut L::LoadRequires<'_>) {
        // We are going to copy the required loader data and send it to the loader.
        // The caller promises to respect the mutable reference so it's OKAY.

        // SAFETY: the caller ensures that the mutable reference is respected.
        let load_requires_copy: L::LoadRequires<'_> = unsafe { std::mem::transmute_copy(data) };
        self.0.set_data(load_requires_copy);
    }
}

/// Used to provide code bytes to the Sleigh.
///
/// Implementors also implement [styx_sleigh_bindings::LoadImage] using
/// [LoaderWrapper]. This is to avoid [crate::Sleigh] users needing to use the ffi api.
pub trait Loader {
    type LoadRequires<'a>;

    /// This will be called before every load.
    fn set_data(&mut self, _data: Self::LoadRequires<'_>) {}

    fn load(&mut self, ptr: &mut [u8], address: u64);
}

impl<L: Loader> styx_sleigh_bindings::LoadImage for LoaderWrapper<L> {
    fn load_fill(&mut self, ptr: &mut [u8], address: &ffi::Address) {
        let address_offset = address.getOffset();
        self.0.load(ptr, address_offset)
    }
}
