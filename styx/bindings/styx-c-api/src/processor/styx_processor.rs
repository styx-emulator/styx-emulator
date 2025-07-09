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
