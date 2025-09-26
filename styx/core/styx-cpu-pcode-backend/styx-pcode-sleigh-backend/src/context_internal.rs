// SPDX-License-Identifier: BSD-2-Clause
use std::pin::Pin;

use styx_sleigh_bindings::ffi;

use crate::sleigh_obj::{DeriveParent, SleighObj};

pub struct ContextInternal {
    pub obj: SleighObj<ffi::ContextInternal>,
}

impl ContextInternal {
    pub fn _set_variable(
        &mut self,
        name: impl AsRef<str>,
        addr_space: *mut ffi::AddrSpace,
        addr_off: u64,
        value: u32,
    ) {
        let name = name.as_ref();
        cxx::let_cxx_string!(name_cxx = name);
        let context_db: Pin<&mut ffi::ContextDatabase> = self.obj.upcast_mut();
        let addr = unsafe { ffi::new_address(addr_space, addr_off) };
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
