// SPDX-License-Identifier: BSD-2-Clause
//! Harness-driven tests of the in-tree [`DefaultExecutor`].
//!
//! Also serve as worked examples for downstream crates testing their own
//! executors through the `test-utils` feature.

use styx_cpu_type::TargetExitReason;

use super::{
    run, verify_universal_invariants, ExecutorTrace, Expectations, ScriptedBackend, ScriptedParams,
    TestProcessor, TestProcessorBuilder,
};
use crate::cpu::DummyBackend;
use crate::executor::{DefaultExecutor, ExecutorKind};

/// Single vCPU on a [`DefaultExecutor`] with the given stride.
fn single_vcpu(stride: u64) -> impl FnOnce(TestProcessorBuilder) -> TestProcessor {
    move |b| {
        b.with_executor(ExecutorKind::stride(DefaultExecutor::with_stride_length(
            stride,
        )))
        .with_vcpu_backend(Box::new(DummyBackend))
        .build()
    }
}

/// Asserts every system tick advanced simulated time by exactly `stride`.
fn assert_uniform_stride(trace: &ExecutorTrace, stride: u64) {
    for (tick_idx, delta) in trace.system_ticks().enumerate() {
        assert_eq!(
            delta.simulated_time, stride,
            "system tick {tick_idx} advanced {} cycles, expected {stride}",
            delta.simulated_time
        );
    }
}

/// The default executor ticks once per stride and advances exactly one stride
/// of simulated time per tick.
#[test]
fn default_executor_stride_cadence() {
    let (trace, snapshot) = run(single_vcpu(1000), 5000_u64).unwrap();
    verify_universal_invariants(
        &trace,
        &snapshot,
        &Expectations::exact_cycles(5000).with_system_ticks(5),
    )
    .unwrap();
    assert_uniform_stride(&trace, 1000);
}

/// A stride of 1 makes the default executor tick on every instruction.
#[test]
fn default_executor_stride_of_one_ticks_every_instruction() {
    let (trace, snapshot) = run(single_vcpu(1), 5_u64).unwrap();
    verify_universal_invariants(
        &trace,
        &snapshot,
        &Expectations::exact_cycles(5).with_system_ticks(5),
    )
    .unwrap();
    assert_uniform_stride(&trace, 1);
}

/// 2 vCPUs where vCPU 0 exits on `exit_on_round`, run for exactly that many
/// strides.
fn scripted_exit(stride: u64, params: ScriptedParams) {
    let exit_round = u64::from(params.exit_on_round);
    let total_cycles = stride * exit_round;
    // The exit round calls record_stride before the halt check, so the partial
    // count lands in cycles_executed while simulated_time gets the full stride.
    // With no partial report the backend is credited the whole stride.
    let expected_executed = stride * (exit_round - 1) + params.partial_count.unwrap_or(stride);

    let (trace, snapshot) = run(
        move |b| {
            b.with_vcpu_backend(Box::new(ScriptedBackend::new(params)))
                .with_vcpu_backend(Box::new(DummyBackend))
                .with_executor(ExecutorKind::stride(DefaultExecutor::with_stride_length(
                    stride,
                )))
                .build()
        },
        total_cycles,
    )
    .unwrap();

    verify_universal_invariants(
        &trace,
        &snapshot,
        &Expectations::exact_cycles(total_cycles).with_system_ticks(exit_round as usize),
    )
    .unwrap();

    // Pins down the exit-round semantics the universal invariants deliberately
    // tolerate. vCPU 0 records its stride on the exit round but has
    // post_stride_processing skipped, so it ticks one fewer time than vCPU 1.
    assert_eq!(
        trace.vcpu_ticks(0).count() as u64,
        exit_round - 1,
        "exiting vcpu should skip post_stride_processing on its exit round"
    );
    assert_eq!(
        trace.vcpu_ticks(1).count() as u64,
        exit_round,
        "non-exiting vcpu should tick every round"
    );

    // The exiting vCPU is simulated for every round it took part in, including
    // the one it exited on, but only runs what the backend reported.
    assert_eq!(
        snapshot.vcpu_simulated[0], total_cycles,
        "exiting vcpu should be simulated for the full run"
    );
    assert_eq!(
        snapshot.vcpu_executed[0], expected_executed,
        "exiting vcpu should run only the instructions the backend reported"
    );
    assert_eq!(
        snapshot.vcpu_executed[1], total_cycles,
        "non-exiting vcpu should execute every cycle it was simulated for"
    );

    assert_uniform_stride(&trace, stride);
}

/// A vCPU that exits on a stride boundary is credited the whole stride, and the
/// round it exits on still completes for the other vCPU.
#[test]
fn scripted_exit_on_stride_boundary() {
    scripted_exit(
        1000,
        ScriptedParams {
            exit_on_round: 2,
            exit_reason: TargetExitReason::BusError,
            partial_count: None,
        },
    );
}

/// A vCPU that exits part way through a stride executes only what it ran. Its
/// simulated time still advances by the full stride.
#[test]
fn scripted_exit_mid_stride_stalls_remaining_cycles() {
    scripted_exit(
        1000,
        ScriptedParams {
            exit_on_round: 3,
            exit_reason: TargetExitReason::HostStopRequest,
            partial_count: Some(500),
        },
    );
}

/// Markers dropped mid-run bracket the ticks that happened between them.
#[test]
fn marks_bracket_a_span_of_ticks() {
    let (trace, snapshot) = super::run_with(single_vcpu(1000), |proc, recorder| {
        proc.executor
            .begin(
                &mut proc.vcpus,
                &mut proc.core,
                &mut proc.plugins,
                &2000_u64,
            )
            .map(|_| ())?;
        recorder.mark("resumed");
        proc.executor
            .begin(
                &mut proc.vcpus,
                &mut proc.core,
                &mut proc.plugins,
                &3000_u64,
            )
            .map(|_| ())?;
        recorder.mark("done");
        Ok(())
    })
    .unwrap();

    verify_universal_invariants(
        &trace,
        &snapshot,
        &Expectations::exact_cycles(5000).with_system_ticks(5),
    )
    .unwrap();
    assert_eq!(trace.between("resumed", "done").system_ticks().count(), 3);
}
