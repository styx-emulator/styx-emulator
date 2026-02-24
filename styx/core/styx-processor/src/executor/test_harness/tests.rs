// SPDX-License-Identifier: BSD-2-Clause
//! Tests of the [`DefaultExecutor`].
//!
//! Also serves as examples for users to test their own executors.

use styx_cpu_type::TargetExitReason;

use super::{
    run, verify_universal_invariants, ExecutorTrace, Expectations, ScriptedBackend, ScriptedParams,
    TestProcessor, TestProcessorBuilder,
};
use crate::cpu::DummyBackend;
use crate::executor::{DefaultExecutor, ExecutorKind};

/// Single vCPU on a [`DefaultExecutor`] with the given stride.
fn test_processor_builder(stride: u64) -> impl FnOnce(TestProcessorBuilder) -> TestProcessor {
    move |b| {
        b.with_executor(ExecutorKind::stride(DefaultExecutor::with_stride_length(
            stride,
        )))
        .with_vcpu_backend(Box::new(DummyBackend))
        .build()
    }
}

/// Asserts every system tick advances simulated time by exactly `stride`.
fn assert_uniform_stride(trace: &ExecutorTrace, stride: u64) {
    for (tick_idx, delta) in trace.system_ticks().enumerate() {
        assert_eq!(
            delta.simulated_time, stride,
            "system tick {tick_idx} advanced {} cycles, expected {stride}",
            delta.simulated_time
        );
    }
}

/// Test ticks once per stride and advances one stride of simulated time.
#[test]
fn executor_stride_cadence() {
    let (trace, snapshot) = run(test_processor_builder(1000), 5000_u64).unwrap();
    verify_universal_invariants(
        &trace,
        &snapshot,
        &Expectations::exact_cycles(5000).with_system_ticks(5),
    )
    .unwrap();
    assert_uniform_stride(&trace, 1000);
}

/// A single step ticks on every instruction.
#[test]
fn single_step_ticks_every_instruction() {
    let (trace, snapshot) = run(test_processor_builder(1), 5_u64).unwrap();
    verify_universal_invariants(
        &trace,
        &snapshot,
        &Expectations::exact_cycles(5).with_system_ticks(5),
    )
    .unwrap();
    assert_uniform_stride(&trace, 1);
}

/// 2 vCPUs where vCPU 0 exits on `params.exit_on_round`.
///
/// vCPU 0 is the "exiting vCPU". vCPU 1 is the "non-exiting vCPU".
///
/// Tests invariants as expected:
///
/// - "Universal" invariants (see [`verify_universal_invariants()`])
/// - vCPU 0 tracks simulated full stride and executed only partial executed instructions.
/// - vCPU 1 tracks simulated and executed full stride.
///
/// Non spec'd checked invariants:
///
/// - Exiting vCPU doesn't run `post_stride_processing`
/// - Non-exiting vCPU(s) DO run `post_stride_processing`
fn scripted_exit(stride: u64, params: ScriptedParams) {
    let exit_round = u64::from(params.exit_on_round);
    let total_cycles = stride * exit_round;

    // A stopped stride should have the partial_count added to cycles_executed
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

    // Normal invariants.
    assert_eq!(
        snapshot.vcpu_simulated[0], total_cycles,
        "exiting vcpu should be simulated for the full run"
    );
    assert_eq!(
        snapshot.vcpu_executed[0], expected_executed,
        "exiting vcpu should run only the instructions the backend reported"
    );
    assert_eq!(
        snapshot.vcpu_simulated[1], total_cycles,
        "non-exiting vcpu should be simulated for the full run"
    );
    assert_eq!(
        snapshot.vcpu_executed[1], total_cycles,
        "non-exiting vcpu should execute every cycle it was simulated for"
    );
    assert_uniform_stride(&trace, stride);

    // These aren't specified by the executor spec, but if the default executor
    // changed them then emulators could break.
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
}

/// A single vCPU exits.
///
/// Ensure other vCPUs also run that stride.
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

/// A single vCPU exits early.
///
/// Simulated time still advances by the full stride.
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

/// Markers between executions count ticks correctly.
#[test]
fn marks_between_executions() {
    let (trace, snapshot) = super::run_with(test_processor_builder(1000), |proc, recorder| {
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
