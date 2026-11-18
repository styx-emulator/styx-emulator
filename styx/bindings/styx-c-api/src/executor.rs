// SPDX-License-Identifier: BSD-2-Clause
use crate::data::StyxFFIErrorPtr;

crate::data::opaque_pointer! {
    pub struct StyxExecutor(styx_emulator::core::executor::ExecutorKind)
}

#[unsafe(no_mangle)]
pub extern "C" fn StyxExecutor_free(e: *mut StyxExecutor) {
    StyxExecutor::free(e)
}

/// Creates a default Executor
#[unsafe(no_mangle)]
pub extern "C" fn StyxExecutor_Executor_default(out: *mut StyxExecutor) -> StyxFFIErrorPtr {
    crate::try_out(out, || {
        let retn = styx_emulator::core::executor::DefaultExecutor::default();
        StyxExecutor::new(styx_emulator::core::executor::ExecutorKind::stride(retn))
    })
}
