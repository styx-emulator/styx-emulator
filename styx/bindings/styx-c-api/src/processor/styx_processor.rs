// SPDX-License-Identifier: BSD-2-Clause
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use styx_emulator::prelude::{ExecutionConstraintConcrete, Forever};

use crate::{data::StyxFFIErrorPtr, processor::StyxEmulationReport, try_out};

crate::data::opaque_pointer! {
    /// A handle to a processor emulator
    pub struct StyxProcessor(Arc<Mutex<styx_emulator::prelude::Processor>>)
}

/// disposes the processor handle
#[no_mangle]
pub extern "C" fn StyxProcessor_free(this: *mut StyxProcessor) {
    StyxProcessor::free(this)
}

/// Start the processor's emulation process, blocking on the current thread until the processor
/// exits.
#[no_mangle]
pub extern "C" fn StyxProcessor_start_blocking(
    processor: StyxProcessor,
    report: *mut StyxEmulationReport,
) -> StyxFFIErrorPtr {
    let mut processor = processor.as_ref()?.lock().unwrap();
    try_out(report, || {
        StyxEmulationReport::new(Box::new(processor.run(Forever)?))
    })
}

/// Start the processor's emulation process, blocking on the current thread until the processor
/// exits. Provide a limit to number of instructions to execute and milliseconds of wall execution
/// time. 0 for either of these values disables that timeout. 0 for both values will run until the
/// processor exits.
#[no_mangle]
pub extern "C" fn StyxProcessor_start_blocking_constraints(
    processor: StyxProcessor,
    instr: u64,
    millis: u64,
    report: *mut StyxEmulationReport,
) -> StyxFFIErrorPtr {
    let mut processor = processor.as_ref()?.lock().unwrap();

    let constraint = ExecutionConstraintConcrete::new(instr, Duration::from_millis(millis));

    try_out(report, || {
        StyxEmulationReport::new(Box::new(processor.run(constraint)?))
    })
}
