// SPDX-License-Identifier: BSD-2-Clause
//! Event trace types recorded during test harness runs.

use std::sync::{Arc, Mutex};

use crate::core::VcpuId;
use crate::executor::time::GlobalDelta;
use crate::executor::Delta;

/// A single observed accounting event.
#[derive(Debug, Clone)]
pub enum ExecutorEvent {
    /// Scenario-dropped marker for a trace span.
    Mark { label: &'static str },
    /// System-level event distributor tick. Fires once per round.
    SystemTick { delta: GlobalDelta },
    /// Per-vCPU event-controller tick. Fires inside `post_stride_processing`.
    VcpuTick { vcpu: VcpuId, delta: Delta },
}

/// One recorded event plus its monotonic sequence number.
#[derive(Debug, Clone)]
pub struct TraceEntry {
    pub seq: u64,
    pub event: ExecutorEvent,
}

/// Shared, clone-able handle used by decorators and test code to append events.
///
/// Cloning produces another handle onto the same underlying log. Use
/// [`TraceRecorder::finish`] to produce the final [`ExecutorTrace`].
#[derive(Clone, Default)]
pub struct TraceRecorder {
    inner: Arc<Mutex<RecorderInner>>,
}

#[derive(Debug, Default)]
struct RecorderInner {
    next_seq: u64,
    entries: Vec<TraceEntry>,
}

impl TraceRecorder {
    pub fn record(&self, event: ExecutorEvent) {
        let mut g = self.inner.lock().expect("trace recorder mutex poisoned");
        let seq = g.next_seq;
        g.next_seq += 1;
        g.entries.push(TraceEntry { seq, event });
    }

    /// Drop a labeled marker into the trace. Useful for `validate()` to query
    /// events that happened between named points in `drive()`.
    pub fn mark(&self, label: &'static str) {
        self.record(ExecutorEvent::Mark { label });
    }

    /// Produce the final trace. Outstanding clones of the recorder may still be
    /// alive; this takes a copy of the log rather than consuming it.
    pub fn finish(&self) -> ExecutorTrace {
        ExecutorTrace {
            entries: self.snapshot(),
        }
    }

    /// Snapshot the current entries. Useful mid-run when the caller wants
    /// introspection before the executor has finished.
    pub fn snapshot(&self) -> Vec<TraceEntry> {
        self.inner.lock().unwrap().entries.clone()
    }
}

/// Final, read-only trace produced by [`TraceRecorder::finish`].
#[derive(Debug, Clone)]
pub struct ExecutorTrace {
    entries: Vec<TraceEntry>,
}

impl ExecutorTrace {
    pub fn entries(&self) -> &[TraceEntry] {
        &self.entries
    }

    pub fn system_ticks(&self) -> impl Iterator<Item = &GlobalDelta> + '_ {
        self.entries.iter().filter_map(|e| match &e.event {
            ExecutorEvent::SystemTick { delta, .. } => Some(delta),
            _ => None,
        })
    }

    pub fn vcpu_ticks(&self, vcpu: VcpuId) -> impl Iterator<Item = &Delta> + '_ {
        self.entries.iter().filter_map(move |e| match &e.event {
            ExecutorEvent::VcpuTick { vcpu: v, delta } if *v == vcpu => Some(delta),
            _ => None,
        })
    }

    /// Total sum of simulated time.
    pub fn total_system_simulated(&self) -> u64 {
        self.system_ticks().map(|d| d.simulated_time).sum()
    }

    pub fn total_vcpu_delta_count(&self, vcpu: VcpuId) -> u64 {
        self.vcpu_ticks(vcpu).map(|d| d.count).sum()
    }

    /// Select the slice of entries strictly between the first `start` marker
    /// and the first `end` marker that follows it. If either marker is absent
    /// the span is empty.
    pub fn between(&self, start: &'static str, end: &'static str) -> ExecutorTraceSpan<'_> {
        let start_idx = self
            .entries
            .iter()
            .position(|e| matches!(e.event, ExecutorEvent::Mark { label } if label == start));
        let Some(s) = start_idx else {
            return ExecutorTraceSpan { entries: &[] };
        };
        let rel_end = self.entries[s + 1..]
            .iter()
            .position(|e| matches!(e.event, ExecutorEvent::Mark { label } if label == end));
        let e = match rel_end {
            Some(r) => s + 1 + r,
            None => return ExecutorTraceSpan { entries: &[] },
        };
        ExecutorTraceSpan {
            entries: &self.entries[s + 1..e],
        }
    }
}

/// A read-only view into a contiguous subsequence of a trace, created by
/// two labeled markers. Returned by [`ExecutorTrace::between`].
///
/// If either marker is missing from the trace the span is empty. If the same
/// label appears multiple times, the **first** occurrence of `start` and the
/// **first** occurrence of `end` after `start` are used.
#[derive(Debug, Clone, Copy)]
pub struct ExecutorTraceSpan<'a> {
    entries: &'a [TraceEntry],
}

impl<'a> ExecutorTraceSpan<'a> {
    pub fn entries(&self) -> &'a [TraceEntry] {
        self.entries
    }

    pub fn system_ticks(&self) -> impl Iterator<Item = &'a GlobalDelta> + 'a {
        self.entries.iter().filter_map(|e| match &e.event {
            ExecutorEvent::SystemTick { delta, .. } => Some(delta),
            _ => None,
        })
    }

    pub fn vcpu_ticks(&self, vcpu: VcpuId) -> impl Iterator<Item = &'a Delta> + 'a {
        self.entries.iter().filter_map(move |e| match &e.event {
            ExecutorEvent::VcpuTick { vcpu: v, delta } if *v == vcpu => Some(delta),
            _ => None,
        })
    }

    pub fn total_system_simulated(&self) -> u64 {
        self.system_ticks().map(|d| d.simulated_time).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::time::GlobalDelta;
    use crate::executor::Delta;
    use std::time::Duration;

    #[test]
    fn recorder_preserves_insertion_order_and_assigns_seq() {
        let rec = TraceRecorder::default();
        rec.record(ExecutorEvent::VcpuTick {
            vcpu: 0,
            delta: Delta {
                time: Duration::from_millis(1),
                count: 500,
            },
        });
        rec.mark("midpoint");
        rec.record(ExecutorEvent::SystemTick {
            delta: GlobalDelta::new(1000, Duration::from_millis(2)),
        });

        let trace = rec.finish();
        let entries = trace.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].seq, 0);
        assert_eq!(entries[1].seq, 1);
        assert_eq!(entries[2].seq, 2);
        assert!(matches!(
            entries[0].event,
            ExecutorEvent::VcpuTick { vcpu: 0, .. }
        ));
        assert!(matches!(
            entries[1].event,
            ExecutorEvent::Mark { label: "midpoint" }
        ));
        assert!(matches!(entries[2].event, ExecutorEvent::SystemTick { .. }));
    }

    #[test]
    fn totals_sum_correctly() {
        let rec = TraceRecorder::default();
        rec.record(ExecutorEvent::SystemTick {
            delta: GlobalDelta::new(1000, Duration::ZERO),
        });
        rec.record(ExecutorEvent::SystemTick {
            delta: GlobalDelta::new(500, Duration::ZERO),
        });
        rec.record(ExecutorEvent::VcpuTick {
            vcpu: 0,
            delta: Delta {
                time: Duration::ZERO,
                count: 1500,
            },
        });
        let trace = rec.finish();
        assert_eq!(trace.total_system_simulated(), 1500);
        assert_eq!(trace.total_vcpu_delta_count(0), 1500);
        assert_eq!(trace.system_ticks().count(), 2);
        assert_eq!(trace.vcpu_ticks(0).count(), 1);
    }

    #[test]
    fn span_selects_events_between_two_marks() {
        use std::time::Duration;
        let rec = TraceRecorder::default();
        rec.mark("before");
        rec.record(ExecutorEvent::SystemTick {
            delta: GlobalDelta::new(100, Duration::ZERO),
        });
        rec.mark("mid");
        rec.record(ExecutorEvent::SystemTick {
            delta: GlobalDelta::new(200, Duration::ZERO),
        });
        rec.mark("after");

        let trace = rec.finish();
        let before_mid = trace.between("before", "mid");
        assert_eq!(before_mid.system_ticks().count(), 1);
        assert_eq!(before_mid.total_system_simulated(), 100);

        let mid_after = trace.between("mid", "after");
        assert_eq!(mid_after.system_ticks().count(), 1);
        assert_eq!(mid_after.total_system_simulated(), 200);
    }

    #[test]
    fn span_missing_marker_is_empty() {
        let trace = TraceRecorder::default().finish();
        let span = trace.between("nope", "nada");
        assert_eq!(span.system_ticks().count(), 0);
    }
}
