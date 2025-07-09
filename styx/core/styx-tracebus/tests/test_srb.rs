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
//! Integration test, verifies `STRACE_PROVIDER=srb` yields consumable events

use std::time::Duration;
use styx_tracebus::{
    strace, strace_teardown, BaseTraceEvent, IPCTracer, TraceProvider, TracerReader,
    TracerReaderOptions, STRACE,
};

#[test]
#[cfg_attr(miri, ignore)]
fn test_strace_srb() {
    std::env::set_var("STRACE_PROVIDER", "srb");
    // Send n trace events, read them back, make sure the backing
    // key does not exist after teardown
    let mut events: Vec<BaseTraceEvent> = Vec::new();
    let n: usize = 5;
    for _ in 0..n {
        events.push(BaseTraceEvent {
            pc: n as u32,
            ..Default::default()
        });
    }
    assert_eq!(n, events.len());

    for e in events.iter_mut() {
        let x = e.clone();
        strace!(x);
    }
    let opts = TracerReaderOptions::new(&STRACE.key());
    let mut rx = IPCTracer::get_consumer(opts.clone()).unwrap();
    let timeout = Duration::from_millis(250);
    for _ in 0..n {
        let val = rx
            .zero_copy_context()
            .recv_timeout::<BaseTraceEvent>(timeout)
            .unwrap()
            .unwrap();
        assert_eq!(val.pc, n as u32);
    }

    let fpath = std::path::Path::new(opts.filename.as_str());
    // teardown removes the trace file
    assert!(fpath.exists());
    strace_teardown!();
    assert!(!fpath.exists());
}
