// SPDX-License-Identifier: BSD-2-Clause
use crate::data::StyxFFIErrorPtr;

crate::data::opaque_pointer! {
    pub struct StyxExecutor(Box<dyn styx_emulator::core::executor::ExecutorImpl>)
}

#[no_mangle]
pub extern "C" fn StyxExecutor_free(e: *mut StyxExecutor) {
    StyxExecutor::free(e)
}

/// Creates a default Executor
#[no_mangle]
pub extern "C" fn StyxExecutor_Executor_default(out: *mut StyxExecutor) -> StyxFFIErrorPtr {
    crate::try_out(out, || {
        let retn = styx_emulator::core::executor::DefaultExecutor;
        StyxExecutor::new(Box::new(retn))
    })
}
