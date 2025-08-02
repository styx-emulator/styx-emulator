// SPDX-License-Identifier: BSD-2-Clause
use styx_emulator::prelude as styx;

crate::data::opaque_pointer! {
    pub struct StyxEmulationReport(Box<styx::EmulationReport>)
}

#[unsafe(no_mangle)]
pub extern "C" fn StyxEmulationReport_free(out: *mut StyxEmulationReport) {
    StyxEmulationReport::free(out)
}

#[unsafe(no_mangle)]
pub extern "C" fn StyxEmulationReport_instructions(this: StyxEmulationReport) -> u64 {
    this.as_ref().unwrap().instructions()
}

/// Get the total wall clock time spent in emulation, in seconds.
#[unsafe(no_mangle)]
pub extern "C" fn StyxEmulationReport_wall_time(this: StyxEmulationReport) -> f64 {
    this.as_ref().unwrap().wall_time.as_secs_f64()
}
