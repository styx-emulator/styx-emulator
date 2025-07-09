// SPDX-License-Identifier: BSD-2-Clause
//! Integration test, verifies `STRACE_PROVIDER=""` (unset) yields no event artifacts

use styx_tracebus::{strace, BaseTraceEvent, TraceProvider, STRACE};

#[test]
#[cfg_attr(miri, ignore)]
/// tests that the [TraceProvider] get set to [NullProvider]
fn test_strace_not_set() {
    std::env::set_var("STRACE_PROVIDER", "");
    strace!(BaseTraceEvent::default());
    let key = STRACE.key();
    assert!(!std::path::Path::new(&key).exists())
}
