// SPDX-License-Identifier: BSD-2-Clause
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
