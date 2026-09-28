// SPDX-License-Identifier: BSD-2-Clause
/// Styx processors run on a simulated cycle count. We refer to this as "time"
/// but all logic uses cycles as a unit. You will sometimes see "wall-time"
/// which is counted using [`Duration`]s but these should not be used for functional
/// behavior. Cycle timing allows for host/guest agnostic timing.
///
/// There are two main counters. Global Time and Local Time. Global time is the "true time" and is
/// reported to peripherals and event distributors. Local or Vcpu time is matches the global
/// time before/after strides (but not during). You can think of this as Vcpus are "caught up".
/// During a stride execution, time is in flux. Vcpus will start out `stride` instructions behind
/// the global time and attempt to execute up to the new global time.
///
/// While `stride` instructions are attempted to be executed, if a vcpu does not fully perform all cycles,
/// this is ignored, similar to a cpu "stalling" for some cycles. This will materialize as a lag between
/// a vcpus cycles_executed and its simulated_time. A vcpu may exit early due to many benign or fatal causes
/// such as a host stop request or a fault.
use std::{ops::Sub, time::Duration};

use crate::cpu::ExecutionReport;

use super::Delta;

/// Per-vCPU time accounting.
///
/// Three independent counters:
/// - [`simulated_time`](Self::simulated_time): cycles the vCPU has been simulated
///   for. At every round boundary this equals [`ProcessorTime::simulated_time`]
///   for every vCPU in the processor, live or exited. Advances by the full
///   stride each round regardless of whether the CPU actually ran that many
///   instructions.
/// - [`cycles_executed`](Self::cycles_executed): instructions actually executed
///   by the CPU backend. May be less than `simulated_time`. The difference
///   between this and `simulated_time` can be thought of as stalled cycles.
///   This metric is for debug purposes and does not drive control flow, i.e.
///   the processor shouldn't care if a vcpu stalls.
/// - [`wall_time`](Self::wall_time): cumulative host wall-clock time spent
///   running this vCPU.
#[derive(Default, Clone, Copy, Debug)]
pub struct VcpuTime {
    simulated_time: u64,
    cycles_executed: u64,
    wall_time: Duration,
}

impl VcpuTime {
    /// Simulated cycles this vCPU has advanced through.
    pub fn simulated_time(&self) -> u64 {
        self.simulated_time
    }

    /// Instructions actually executed by the CPU backend. Debug-only.
    pub fn cycles_executed(&self) -> u64 {
        self.cycles_executed
    }

    /// Cumulative host wall-clock time spent running this vCPU.
    pub fn wall_time(&self) -> Duration {
        self.wall_time
    }

    /// Add to the simulated clock by `cycles`. Saturating.
    pub fn add_simulated(&mut self, cycles: u64) {
        self.simulated_time = self.simulated_time.saturating_add(cycles);
    }

    /// Add executed instructions to `cycles_executed`. Saturating.
    pub fn add_executed(&mut self, cycles: u64) {
        self.cycles_executed = self.cycles_executed.saturating_add(cycles);
    }

    /// Add host wall-clock time. Saturating.
    pub fn add_wall_time(&mut self, d: Duration) {
        self.wall_time = self.wall_time.saturating_add(d);
    }

    /// Record the outcome of one stride.
    ///
    /// - `simulated_time` always advances by the full `stride` even when the backend
    ///   executes fewer instructions.
    /// - `cycles_executed` advances by `report.instructions_executed.unwrap_or(stride)`
    ///   (a backend that did not report a count is treated as having run the full stride).
    /// - `wall_time` advances by `wall`.
    pub fn record_stride(&mut self, report: &ExecutionReport, stride: u64, wall: Duration) {
        let instr_executed = report.instructions_executed.unwrap_or(stride);
        self.add_executed(instr_executed);
        self.add_simulated(stride);
        self.add_wall_time(wall);
    }
}

impl Sub for VcpuTime {
    type Output = Delta;

    fn sub(self, rhs: Self) -> Self::Output {
        Delta {
            time: self.wall_time - rhs.wall_time,
            count: self.cycles_executed - rhs.cycles_executed,
        }
    }
}

/// Processor-wide simulated cycle clock.
///
/// Advances by the stride length once per round, after all vCPUs have
/// finished their stride for that round. Peripherals and the event
/// distributor schedule against this clock via [`GlobalDelta`].
#[derive(Default, Clone, Debug)]
pub struct ProcessorTime {
    simulated_time: u64,
}

impl ProcessorTime {
    /// Cycles the processor has advanced through.
    pub fn simulated_time(&self) -> u64 {
        self.simulated_time
    }

    /// Advance the simulated clock by `cycles`. Saturating.
    pub fn advance(&mut self, cycles: u64) {
        self.simulated_time = self.simulated_time.saturating_add(cycles);
    }
}

/// Per-stride timekeeping delta passed to the event distributor and peripherals.
///
/// Carries simulated-cycle advancement and host wall-clock duration.
/// No per-vcpu breakdown included to separate vcpu/processor time scales.
#[derive(Default, Clone, Debug)]
pub struct GlobalDelta {
    /// Cycles the processor advanced this round. Equal to the stride length
    /// for a full round.
    pub simulated_time: u64,
    /// Measured host wall-clock duration of the round.
    pub wall_time: Duration,
}

impl GlobalDelta {
    /// Create a new `GlobalDelta` from a simulated-cycle advancement and a measured wall-clock duration.
    pub fn new(simulated_time: u64, wall_time: Duration) -> Self {
        Self {
            simulated_time,
            wall_time,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use styx_cpu_type::TargetExitReason;

    fn report(instr_executed: Option<u64>) -> ExecutionReport {
        ExecutionReport {
            exit_reason: TargetExitReason::InstructionCountComplete,
            instructions_executed: instr_executed,
            last_packet_order: None,
        }
    }

    #[test]
    fn record_stride_full_report_matches_stride() {
        let mut t = VcpuTime::default();
        t.record_stride(&report(Some(1000)), 1000, Duration::from_millis(5));
        assert_eq!(t.simulated_time(), 1000);
        assert_eq!(t.cycles_executed(), 1000);
        assert_eq!(t.wall_time(), Duration::from_millis(5));
    }

    #[test]
    fn record_stride_partial_report_leaves_stall() {
        let mut t = VcpuTime::default();
        t.record_stride(&report(Some(500)), 1000, Duration::from_millis(3));
        assert_eq!(t.simulated_time(), 1000);
        assert_eq!(t.cycles_executed(), 500);
        assert_eq!(t.wall_time(), Duration::from_millis(3));
    }

    #[test]
    fn record_stride_none_report_treats_as_full() {
        let mut t = VcpuTime::default();
        t.record_stride(&report(None), 1000, Duration::from_millis(1));
        assert_eq!(t.simulated_time(), 1000);
        assert_eq!(t.cycles_executed(), 1000);
        assert_eq!(t.wall_time(), Duration::from_millis(1));
    }

    #[test]
    fn record_stride_accumulates_across_rounds() {
        let mut t = VcpuTime::default();
        t.record_stride(&report(Some(1000)), 1000, Duration::from_millis(2));
        t.record_stride(&report(Some(900)), 1000, Duration::from_millis(2));
        t.record_stride(&report(None), 1000, Duration::from_millis(2));
        assert_eq!(t.simulated_time(), 3000);
        assert_eq!(t.cycles_executed(), 1000 + 900 + 1000);
        assert_eq!(t.wall_time(), Duration::from_millis(6));
    }

    #[test]
    fn advance_simulated_and_add_executed_saturate() {
        let mut t = VcpuTime::default();
        t.add_simulated(u64::MAX);
        t.add_simulated(1);
        assert_eq!(t.simulated_time(), u64::MAX);

        t.add_executed(u64::MAX);
        t.add_executed(1);
        assert_eq!(t.cycles_executed(), u64::MAX);
    }

    #[test]
    fn processor_time_advance_saturates() {
        let mut p = ProcessorTime::default();
        p.advance(1000);
        assert_eq!(p.simulated_time(), 1000);
        p.advance(u64::MAX);
        assert_eq!(p.simulated_time(), u64::MAX);
    }

    #[test]
    fn global_delta_constructs() {
        let d = GlobalDelta::new(1000, Duration::from_millis(5));
        assert_eq!(d.simulated_time, 1000);
        assert_eq!(d.wall_time, Duration::from_millis(5));
    }
}
