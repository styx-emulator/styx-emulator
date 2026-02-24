// SPDX-License-Identifier: BSD-2-Clause
//! Universal correctness invariants checked against a recorded trace.

use crate::core::VcpuId;
use crate::executor::test_harness::trace::{ExecutorEvent, ExecutorTrace};
use crate::processor::PerVcpu;

/// Snapshot of processor state captured immediately after the run completes.
/// Used to validate that the trace totals match reality.
#[derive(Debug, Clone)]
pub struct PostRunSnapshot {
    /// [`ProcessorTime::simulated_time`](crate::executor::time::ProcessorTime::simulated_time).
    pub core_simulated: u64,
    /// Per-vCPU [`VcpuTime::simulated_time`](crate::executor::time::VcpuTime::simulated_time),
    /// which advances by the full stride every round.
    pub vcpu_simulated: PerVcpu<u64>,
    /// Per-vCPU [`VcpuTime::cycles_executed`](crate::executor::time::VcpuTime::cycles_executed).
    /// Advances only by instructions the backend ran. Gap against
    /// `vcpu_simulated` is stalled cycles. Only way to observe a stride that
    /// ended early.
    pub vcpu_executed: PerVcpu<u64>,
}

/// What the caller expects the run to have done, beyond the invariants that
/// hold for every executor.
///
/// A run that stops at fixed points knows how many system ticks to expect and
/// sets `system_ticks = Some(n)`. A run that stops wherever a breakpoint lands
/// (GDB) cannot know that number, so it leaves the field `None` and only checks
/// the cycle total.
#[derive(Debug, Clone)]
pub struct Expectations {
    /// Total simulated cycles the run should advance. The check is
    /// `abs(core_simulated - total_cycles) <= cycle_tolerance`.
    pub total_cycles: u64,

    /// How far `total_cycles` may be off. Zero when the run always executes the
    /// same number of cycles. When a breakpoint can stop the run part way
    /// through a stride, allow at least one stride.
    pub cycle_tolerance: u64,

    /// If `Some(n)`, also check that exactly `n` system ticks happened. `None`
    /// skips that check, for runs whose tick count is not fixed (gdb, fuzz).
    pub system_ticks: Option<usize>,
}

impl Expectations {
    /// Expect an exact cycle count with no tolerance and an unconstrained tick
    /// count.
    pub fn exact_cycles(total_cycles: u64) -> Self {
        Self {
            total_cycles,
            cycle_tolerance: 0,
            system_ticks: None,
        }
    }

    /// Also require exactly `n` system ticks.
    pub fn with_system_ticks(mut self, n: usize) -> Self {
        self.system_ticks = Some(n);
        self
    }

    /// Allow the cycle total to be off by up to `tolerance`.
    pub fn with_cycle_tolerance(mut self, tolerance: u64) -> Self {
        self.cycle_tolerance = tolerance;
        self
    }
}

/// Reason a universal invariant failed. All variants carry enough context to
/// diagnose the executor under test.
#[derive(Debug)]
pub enum InvariantViolation {
    /// `sum(SystemTick.delta.simulated)` disagrees with `core.simulated_time()`.
    /// The executor is not calling `core.time.advance()` in step with the
    /// `GlobalDelta` it hands to the event distributor.
    CoreTimeMismatch { trace_sum: u64, core_simulated: u64 },

    /// SystemTick recorded with no VcpuTick since the previous SystemTick, or
    /// since the start of the trace. `post_stride_processing` was not called
    /// for any vCPU before the event distributor ticked.
    MissingPostStrideProcessing { tick_index: usize },

    /// Total simulated cycles fell outside `[expected - tolerance, expected + tolerance]`.
    TotalCyclesOutOfTolerance {
        expected: u64,
        tolerance: u64,
        actual: u64,
    },

    /// [`Expectations::system_ticks`] did not match the recorded count.
    UnexpectedTickCount { expected: usize, actual: usize },

    /// A vCPU executed more instructions than it was simulated for. A stride
    /// credits `simulated_time` with its full nominal length and
    /// `cycles_executed` with what the backend ran, so executed can only lag.
    /// Executed running ahead means the executor advanced `cycles_executed`
    /// with no matching `add_simulated`. Usual causes: recording a stride
    /// twice, or passing `record_stride` a shorter stride than the backend
    /// was asked to run.
    VcpuExecutedExceedsSimulated {
        vcpu: VcpuId,
        executed: u64,
        simulated: u64,
    },

    /// A vCPU never ticked in the first round. Every vCPU is live when
    /// emulation starts, so the executor must run `post_stride_processing` for
    /// all of them before the first event-distributor tick.
    VcpuNeverStarted { vcpu: VcpuId },

    /// A vCPU stopped ticking and then started again. A vCPU may exit
    /// permanently. An executor that skips a live vCPU for a round and picks
    /// it back up later has dropped events on the floor.
    VcpuResumedAfterExiting {
        vcpu: VcpuId,
        exited_after_tick: usize,
        resumed_at_tick: usize,
    },

    /// A vCPU ticked at least once but its `simulated_time()` is still zero:
    /// the executor ran `post_stride_processing` without ever calling
    /// `vcpu.time.record_stride()`.
    VcpuTimeNeverRecorded { vcpu: VcpuId },
}

/// Check the universal correctness invariants against a recorded trace and a
/// post-run state snapshot.
///
/// These hold for **every** executor, stride-based or custom. They exist to
/// enforce the accounting contract that [`CustomExecutor`] documents but the
/// type system cannot: call `post_stride_processing` per vCPU stride, tick the
/// event distributor, and keep `vcpu.time.record_stride()` /
/// `core.time.advance()` in step with both.
///
/// Invariants checked:
/// 1. `sum(SystemTick.delta.simulated) == snapshot.core_simulated`.
/// 2. Every SystemTick is preceded (since the last SystemTick or trace start)
///    by at least one VcpuTick, which proves the executor called
///    `post_stride_processing` at least once per round.
/// 3. Every vCPU ticks in the first round. Once a vCPU stops ticking it never
///    ticks again.
/// 4. Every vCPU that ticked has non-zero `simulated_time()`.
/// 5. No vCPU's `cycles_executed()` exceeds its `simulated_time()`. A vCPU may
///    stall, running fewer instructions than the stride it was simulated for.
///    It can never run more.
/// 6. Total simulated cycles falls within
///    `expect.total_cycles +- expect.cycle_tolerance`.
/// 7. If `expect.system_ticks.is_some()`, the count matches exactly.
///
/// Note that invariant 3 is deliberately weaker than "every vCPU ticks every
/// round", and invariants 4 and 5 weaker than "trace totals equal per-vCPU
/// `simulated_time()`". The stronger forms are violated by a vCPU
/// that exits part way through a round.
///
/// [`CustomExecutor`]: crate::executor::CustomExecutor
pub fn verify_universal_invariants(
    trace: &ExecutorTrace,
    snapshot: &PostRunSnapshot,
    expect: &Expectations,
) -> Result<(), InvariantViolation> {
    // (1) Core time consistency.
    let trace_sum = trace.total_system_simulated();
    if trace_sum != snapshot.core_simulated {
        return Err(InvariantViolation::CoreTimeMismatch {
            trace_sum,
            core_simulated: snapshot.core_simulated,
        });
    }

    verify_vcpu_tick_coverage(trace, snapshot.vcpu_simulated.len())?;

    // (4) A vCPU that ran post_stride_processing must also have recorded time.
    for (vcpu, &simulated) in snapshot.vcpu_simulated.enumerate() {
        if simulated == 0 && trace.vcpu_ticks(vcpu).next().is_some() {
            return Err(InvariantViolation::VcpuTimeNeverRecorded { vcpu });
        }
    }

    // (5) A vCPU may stall but can never run more than it was simulated for.
    // A snapshot whose two lists disagree in length is a harness bug, not an
    // executor one, so a missing counterpart is skipped rather than reported.
    for (vcpu, &executed) in snapshot.vcpu_executed.enumerate() {
        let Some(&simulated) = snapshot.vcpu_simulated.get(vcpu) else {
            continue;
        };
        if executed > simulated {
            return Err(InvariantViolation::VcpuExecutedExceedsSimulated {
                vcpu,
                executed,
                simulated,
            });
        }
    }

    // (6) Total cycles within tolerance.
    let diff = expect.total_cycles.abs_diff(snapshot.core_simulated);
    if diff > expect.cycle_tolerance {
        return Err(InvariantViolation::TotalCyclesOutOfTolerance {
            expected: expect.total_cycles,
            tolerance: expect.cycle_tolerance,
            actual: snapshot.core_simulated,
        });
    }

    // (7) Optional exact tick count.
    if let Some(expected) = expect.system_ticks {
        let actual = trace.system_ticks().count();
        if actual != expected {
            return Err(InvariantViolation::UnexpectedTickCount { expected, actual });
        }
    }

    Ok(())
}

/// Invariants (2) and (3): per-round `post_stride_processing` coverage.
///
/// Walks the trace one round at a time, where a round is the run of events
/// terminated by a SystemTick, and tracks which vCPUs ticked in each. Events
/// after the final SystemTick belong to an unterminated round and are ignored;
/// the executor may have been stopped part way through it.
fn verify_vcpu_tick_coverage(
    trace: &ExecutorTrace,
    vcpu_count: usize,
) -> Result<(), InvariantViolation> {
    // `None` until a vCPU misses a round, then the index of the last round it
    // was seen in. An exited vCPU that ticks again fails invariant (3).
    let mut exited_after: Vec<Option<usize>> = vec![None; vcpu_count];
    let mut ticked_this_round = vec![false; vcpu_count];
    let mut round = 0;

    for entry in trace.entries() {
        match &entry.event {
            ExecutorEvent::VcpuTick { vcpu, .. } => {
                let idx = usize::from(*vcpu);
                if let Some(exited_after_tick) = exited_after.get(idx).copied().flatten() {
                    return Err(InvariantViolation::VcpuResumedAfterExiting {
                        vcpu: *vcpu,
                        exited_after_tick,
                        resumed_at_tick: round,
                    });
                }
                if let Some(seen) = ticked_this_round.get_mut(idx) {
                    *seen = true;
                }
            }
            ExecutorEvent::SystemTick { .. } => {
                if !ticked_this_round.iter().any(|seen| *seen) {
                    return Err(InvariantViolation::MissingPostStrideProcessing {
                        tick_index: round,
                    });
                }
                for (idx, seen) in ticked_this_round.iter_mut().enumerate() {
                    if !*seen && exited_after[idx].is_none() {
                        // First round this vCPU sat out. Round 0 means it
                        // never started, which no executor may do.
                        if round == 0 {
                            let vcpu = idx.try_into().expect("vcpu count fits VcpuId");
                            return Err(InvariantViolation::VcpuNeverStarted { vcpu });
                        }
                        exited_after[idx] = Some(round - 1);
                    }
                    *seen = false;
                }
                round += 1;
            }
            ExecutorEvent::Mark { .. } => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::test_harness::trace::{ExecutorEvent, TraceRecorder};
    use crate::executor::time::GlobalDelta;
    use crate::executor::Delta;
    use std::time::Duration;

    fn push_tick(rec: &TraceRecorder, n: u64) {
        rec.record(ExecutorEvent::SystemTick {
            delta: GlobalDelta::new(n, Duration::ZERO),
        });
    }

    fn push_vtick(rec: &TraceRecorder, v: VcpuId, n: u64) {
        rec.record(ExecutorEvent::VcpuTick {
            vcpu: v,
            delta: Delta {
                time: Duration::ZERO,
                count: n,
            },
        });
    }

    /// A single-vCPU run that satisfies every invariant should pass.
    #[test]
    fn all_invariants_satisfied() {
        let rec = TraceRecorder::default();
        for _ in 0..5 {
            push_vtick(&rec, 0, 1000);
            push_tick(&rec, 1000);
        }
        let snap = PostRunSnapshot {
            core_simulated: 5000,
            vcpu_simulated: PerVcpu::collect([5000]).unwrap(),
            vcpu_executed: PerVcpu::collect([5000]).unwrap(),
        };
        let expect = Expectations::exact_cycles(5000).with_system_ticks(5);
        verify_universal_invariants(&rec.finish(), &snap, &expect).unwrap();
    }

    /// Trace system-tick total disagreeing with `core.simulated_time()` fails.
    #[test]
    fn core_time_mismatch_fails() {
        let rec = TraceRecorder::default();
        push_vtick(&rec, 0, 1000);
        push_tick(&rec, 1000);
        let snap = PostRunSnapshot {
            core_simulated: 5000,
            vcpu_simulated: PerVcpu::collect([5000]).unwrap(),
            vcpu_executed: PerVcpu::collect([5000]).unwrap(),
        };
        let err =
            verify_universal_invariants(&rec.finish(), &snap, &Expectations::exact_cycles(5000))
                .unwrap_err();
        assert!(
            matches!(err, InvariantViolation::CoreTimeMismatch { .. }),
            "got {err:?}"
        );
    }

    /// A system tick with no preceding vCPU tick fails.
    #[test]
    fn missing_post_stride_processing_fails() {
        let rec = TraceRecorder::default();
        push_tick(&rec, 1000);
        let snap = PostRunSnapshot {
            core_simulated: 1000,
            vcpu_simulated: PerVcpu::collect([0]).unwrap(),
            vcpu_executed: PerVcpu::collect([0]).unwrap(),
        };
        let err =
            verify_universal_invariants(&rec.finish(), &snap, &Expectations::exact_cycles(1000))
                .unwrap_err();
        assert!(
            matches!(err, InvariantViolation::MissingPostStrideProcessing { .. }),
            "got {err:?}"
        );
    }

    /// A vCPU that exits mid-run is tolerated and skips `post_stride_processing` for vCPU that exited.
    #[test]
    fn per_vcpu_exit_is_tolerated() {
        let rec = TraceRecorder::default();
        push_vtick(&rec, 0, 1000);
        push_vtick(&rec, 1, 1000);
        push_tick(&rec, 1000);
        push_vtick(&rec, 1, 1000);
        push_tick(&rec, 1000);
        let snap = PostRunSnapshot {
            core_simulated: 2000,
            vcpu_simulated: PerVcpu::collect([2000, 2000]).unwrap(),
            vcpu_executed: PerVcpu::collect([2000, 2000]).unwrap(),
        };
        let expect = Expectations::exact_cycles(2000).with_system_ticks(2);
        verify_universal_invariants(&rec.finish(), &snap, &expect).unwrap();
    }

    /// A vCPU skipped for a round and then picked back up fails. An executor
    /// may drop an exited vCPU but may not stall a live one.
    #[test]
    fn vcpu_resuming_after_a_skipped_round_fails() {
        let rec = TraceRecorder::default();
        push_vtick(&rec, 0, 1000);
        push_vtick(&rec, 1, 1000);
        push_tick(&rec, 1000);
        // vcpu 1 sits out round 1 ...
        push_vtick(&rec, 0, 1000);
        push_tick(&rec, 1000);
        // ... then comes back in round 2.
        push_vtick(&rec, 0, 1000);
        push_vtick(&rec, 1, 1000);
        push_tick(&rec, 1000);
        let snap = PostRunSnapshot {
            core_simulated: 3000,
            vcpu_simulated: PerVcpu::collect([3000, 2000]).unwrap(),
            vcpu_executed: PerVcpu::collect([3000, 2000]).unwrap(),
        };
        let err =
            verify_universal_invariants(&rec.finish(), &snap, &Expectations::exact_cycles(3000))
                .unwrap_err();
        assert!(
            matches!(
                err,
                InvariantViolation::VcpuResumedAfterExiting {
                    vcpu: 1,
                    exited_after_tick: 0,
                    resumed_at_tick: 2,
                }
            ),
            "got {err:?}"
        );
    }

    /// An executor that never runs a vCPU at all fails, even though some other
    /// vCPU ticks every round.
    #[test]
    fn vcpu_never_started_fails() {
        let rec = TraceRecorder::default();
        for _ in 0..2 {
            push_vtick(&rec, 0, 1000);
            push_tick(&rec, 1000);
        }
        let snap = PostRunSnapshot {
            core_simulated: 2000,
            vcpu_simulated: PerVcpu::collect([2000, 0]).unwrap(),
            vcpu_executed: PerVcpu::collect([2000, 0]).unwrap(),
        };
        let err =
            verify_universal_invariants(&rec.finish(), &snap, &Expectations::exact_cycles(2000))
                .unwrap_err();
        assert!(
            matches!(err, InvariantViolation::VcpuNeverStarted { vcpu: 1 }),
            "got {err:?}"
        );
    }

    /// `post_stride_processing` without `record_stride` fails.
    #[test]
    fn vcpu_time_never_recorded_fails() {
        let rec = TraceRecorder::default();
        push_vtick(&rec, 0, 1000);
        push_tick(&rec, 1000);
        let snap = PostRunSnapshot {
            core_simulated: 1000,
            vcpu_simulated: PerVcpu::collect([0]).unwrap(),
            vcpu_executed: PerVcpu::collect([0]).unwrap(),
        };
        let err =
            verify_universal_invariants(&rec.finish(), &snap, &Expectations::exact_cycles(1000))
                .unwrap_err();
        assert!(
            matches!(err, InvariantViolation::VcpuTimeNeverRecorded { vcpu: 0 }),
            "got {err:?}"
        );
    }

    /// A vCPU that stalled, running fewer cycles than it was simulated for,
    /// passes. Normal outcome of a stride that exited early.
    #[test]
    fn stalled_vcpu_is_tolerated() {
        let rec = TraceRecorder::default();
        push_vtick(&rec, 0, 1000);
        push_tick(&rec, 1000);
        let snap = PostRunSnapshot {
            core_simulated: 1000,
            vcpu_simulated: PerVcpu::collect([1000]).unwrap(),
            vcpu_executed: PerVcpu::collect([600]).unwrap(),
        };
        verify_universal_invariants(&rec.finish(), &snap, &Expectations::exact_cycles(1000))
            .unwrap();
    }

    /// A vCPU that ran more than it was simulated for fails.
    #[test]
    fn vcpu_executing_past_its_simulated_time_fails() {
        let rec = TraceRecorder::default();
        push_vtick(&rec, 0, 1000);
        push_tick(&rec, 1000);
        let snap = PostRunSnapshot {
            core_simulated: 1000,
            vcpu_simulated: PerVcpu::collect([1000]).unwrap(),
            vcpu_executed: PerVcpu::collect([1500]).unwrap(),
        };
        let err =
            verify_universal_invariants(&rec.finish(), &snap, &Expectations::exact_cycles(1000))
                .unwrap_err();
        assert!(
            matches!(
                err,
                InvariantViolation::VcpuExecutedExceedsSimulated {
                    vcpu: 0,
                    executed: 1500,
                    simulated: 1000,
                }
            ),
            "got {err:?}"
        );
    }

    /// A system tick count other than the expected one fails.
    #[test]
    fn expected_tick_count_enforced() {
        let rec = TraceRecorder::default();
        for _ in 0..3 {
            push_vtick(&rec, 0, 1000);
            push_tick(&rec, 1000);
        }
        let snap = PostRunSnapshot {
            core_simulated: 3000,
            vcpu_simulated: PerVcpu::collect([3000]).unwrap(),
            vcpu_executed: PerVcpu::collect([3000]).unwrap(),
        };
        let expect = Expectations::exact_cycles(3000).with_system_ticks(5);
        let err = verify_universal_invariants(&rec.finish(), &snap, &expect).unwrap_err();
        assert!(
            matches!(err, InvariantViolation::UnexpectedTickCount { .. }),
            "got {err:?}"
        );
    }

    /// A cycle total inside the stated tolerance passes.
    #[test]
    fn tolerance_allows_small_mismatch() {
        let rec = TraceRecorder::default();
        push_vtick(&rec, 0, 950);
        push_tick(&rec, 950);
        let snap = PostRunSnapshot {
            core_simulated: 950,
            vcpu_simulated: PerVcpu::collect([950]).unwrap(),
            vcpu_executed: PerVcpu::collect([950]).unwrap(),
        };
        let expect = Expectations::exact_cycles(1000).with_cycle_tolerance(100);
        verify_universal_invariants(&rec.finish(), &snap, &expect).unwrap();
    }
}
