// SPDX-License-Identifier: BSD-2-Clause
//! Integration test, verifies `STRACE_PROVIDER="null"` yields no event artifacts

use styx_tracebus::{strace, BaseTraceEvent, TraceProvider, STRACE};

#[test]
#[cfg_attr(miri, ignore)]
fn test_strace_null() {
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("STRACE_PROVIDER", "null") };
    strace!(BaseTraceEvent::default());
    let key = STRACE.key();
    assert!(!std::path::Path::new(&key).exists())
}
