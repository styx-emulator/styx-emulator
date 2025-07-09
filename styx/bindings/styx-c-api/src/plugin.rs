// SPDX-License-Identifier: BSD-2-Clause
use crate::data::StyxFFIErrorPtr;

crate::data::opaque_pointer! {
    pub struct StyxPlugin(Box<dyn styx_emulator::core::plugins::UninitPlugin>)
}

#[no_mangle]
pub extern "C" fn StyxPlugin_free(ptr: *mut StyxPlugin) {
    StyxPlugin::free(ptr)
}

#[no_mangle]
pub extern "C" fn StyxPlugin_StyxTracePlugin_default(out: *mut StyxPlugin) -> StyxFFIErrorPtr {
    crate::try_out(out, || {
        let out = styx_emulator::plugins::styx_trace::StyxTracePlugin::default();
        StyxPlugin::new(Box::new(out))
    })
}

#[no_mangle]
pub extern "C" fn StyxPlugin_ProcessorTracingPlugin_default(
    out: *mut StyxPlugin,
) -> StyxFFIErrorPtr {
    crate::try_out(out, || {
        let out = styx_emulator::plugins::tracing_plugins::ProcessorTracingPlugin;
        StyxPlugin::new(Box::new(out))
    })
}
