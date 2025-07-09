// SPDX-License-Identifier: BSD-2-Clause
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
