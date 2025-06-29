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
use std::pin::Pin;

use styx_sleigh_bindings::ffi;

use crate::sleigh_obj::{DeriveParent, SleighObj};

pub struct ContextInternal {
    pub obj: SleighObj<ffi::ContextInternal>,
}

impl ContextInternal {
    pub fn set_variable(&mut self, name: impl AsRef<str>, addr_space: *mut ffi::AddrSpace, addr_off: u64, value: u32) {
        let name = name.as_ref();
        cxx::let_cxx_string!(name_cxx = name);
        let context_db: Pin<&mut ffi::ContextDatabase> = self.obj.upcast_mut();
        let addr  = unsafe { ffi::new_address(addr_space, addr_off) };
        // TODO: don't unwrap
        // TODO: deallocate
        context_db.setVariable(&name_cxx, addr.as_ref().unwrap(), value);
        // invalidate the cache here
    }
}

impl Default for ContextInternal {
    fn default() -> Self {
        Self {
            obj: SleighObj::from_unique_ptr(ffi::new_context_internal()).unwrap(),
        }
    }
}

unsafe impl DeriveParent<ffi::ContextDatabase> for SleighObj<ffi::ContextInternal> {}
