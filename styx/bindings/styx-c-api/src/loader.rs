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
use crate::data::StyxFFIErrorPtr;

crate::data::opaque_pointer! {
    pub struct StyxLoader(Box<dyn styx_emulator::prelude::Loader>)
}

#[unsafe(no_mangle)]
pub extern "C" fn StyxLoader_free(ptr: *mut StyxLoader) {
    StyxLoader::free(ptr)
}

macro_rules! styx_loader_impl {
    ($n:ident($t:ty)) => {
        ::paste::paste! {
            #[unsafe(no_mangle)]
            pub extern "C" fn [< StyxLoader_ $n:camel _new >](out: *mut StyxLoader) -> StyxFFIErrorPtr {
                crate::try_out(out, || {
                    let item = <$t as Default>::default();
                    StyxLoader::new(Box::new(item))
                })
            }
        }
    };
}

styx_loader_impl! {
    BlackfinLDRLoader(styx_emulator::core::loader::BlackfinLDRLoader)
}
styx_loader_impl! {
    ElfLoader(styx_emulator::core::loader::ElfLoader)
}
styx_loader_impl! {
    RawLoader(styx_emulator::core::loader::RawLoader)
}
