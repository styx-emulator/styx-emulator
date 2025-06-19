// SPDX-License-Identifier: BSD-2-Clause
use styx_sleigh_bindings::ffi;

use crate::sleigh_obj::{DeriveParent, SleighObj};

pub struct ContextInternal {
    pub obj: SleighObj<ffi::ContextInternal>,
}

impl Default for ContextInternal {
    fn default() -> Self {
        Self {
            obj: SleighObj::from_unique_ptr(ffi::new_context_internal()).unwrap(),
        }
    }
}

unsafe impl DeriveParent<ffi::ContextDatabase> for SleighObj<ffi::ContextInternal> {}
