// SPDX-License-Identifier: BSD-2-Clause
use std::pin::Pin;

use styx_sleigh_bindings::ffi;

use crate::sleigh_obj::{DeriveParent, SleighObj};

pub struct ContextInternal {
    pub obj: SleighObj<ffi::ContextInternal>,
}

impl ContextInternal {
    pub fn set_variable_default(&mut self, name: impl AsRef<str>, value: u32) {
        let name = name.as_ref();
        cxx::let_cxx_string!(name_cxx = name);
        let context_db: Pin<&mut ffi::ContextDatabase> = self.obj.upcast_mut();
        context_db.setVariableDefault(&name_cxx, value);
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
