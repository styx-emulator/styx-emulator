// SPDX-License-Identifier: BSD-2-Clause
//! GDB plugin tests against the PPC405 example processors.
//!
//! [`multicore`] covers multi-core behavior (thread listing, per-core state,
//! breakpoints, watchpoints). [`nexti`] covers stepping over a call.
use gdb_multicore_ppc::{DualPpc405Builder, SinglePpc405Builder};
use styx_emulator::arch::ppc32::gdb_targets::Ppc4xxTargetDescription;
use styx_emulator::plugins::gdb::{GDBOptions, StepIRQs};
use styx_emulator::prelude::*;
use styx_integration_tests::gdb_harness::GdbHarness;

/// PPC32 instruction size.
const INSTRUCTION_SIZE: u64 = 4;

/// GDB options shared by every harness in this file.
const GDB_OPTIONS: GDBOptions = GDBOptions {
    step_irqs: StepIRQs::Disabled,
    cpu_epoch: 1024,
};

/// Path to the object file holding the firmware's symbols, assembled from
/// `firmware/firmware.S` at build time by `build.rs` (see `FIRMWARE_OBJ_FILE`).
fn symbol_file() -> String {
    env!("FIRMWARE_OBJ_FILE").to_string()
}

/// Read a big-endian u32 from target memory through GDB.
fn read_u32(h: &GdbHarness, addr: u64) -> u32 {
    let bytes = h.read_memory(addr, 4).unwrap();
    u32::from_be_bytes(bytes.try_into().unwrap())
}

fn harness(builder: ProcessorBuilder) -> GdbHarness {
    GdbHarness::from_processor_builder_options::<Ppc4xxTargetDescription>(builder, GDB_OPTIONS)
}

/// Harness around the single-core processor.
fn single_core_harness() -> GdbHarness {
    harness(ProcessorBuilder::default().with_builder(SinglePpc405Builder::default()))
}

/// Harness around the two-core processor.
fn dual_core_harness() -> GdbHarness {
    harness(ProcessorBuilder::default().with_builder(DualPpc405Builder::default()))
}

/// Automated multi-core GDB tests for the two-core PPC405 example.
mod multicore {
    use super::*;
    use gdb_multicore_ppc::{
        CODE_BASE_0, CODE_BASE_1, PRIV_BASE_0, PRIV_BASE_1, PRIV_STW_OFFSET, SHARED_COUNTER,
    };
    use styx_integration_tests::gdb_harness;

    /// Build a harness around the two-core processor, with the cores free-running
    /// relative to each other. The tests below assert on the non-selected core's
    /// progress, which scheduler locking would suppress.
    fn harness() -> GdbHarness {
        let harness = dual_core_harness();
        // Styx only supports `off`.
        harness
            .set_scheduler_locking(gdb_harness::SchedulerLockingMode::Off)
            .unwrap();
        harness
    }

    /// Test every vCPU is exposed to gdb as a thread, not just vCPU 0.
    #[test]
    fn test_two_threads_present() {
        let h = harness();
        let threads = h.list_threads().unwrap();
        assert_eq!(
            threads.len(),
            2,
            "expected 2 gdb threads (cores), got {threads:?}"
        );
    }

    /// Test register reads route to the selected vCPU (r3 and pc), not always vCPU 0.
    #[test]
    fn test_cores_distinct() {
        let h = harness();
        h.select_thread(1).unwrap();
        let regs_t1 = h.list_registers().unwrap();
        let (r3_t1, pc_t1) = (regs_t1["r3"], regs_t1["pc"]);
        h.select_thread(2).unwrap();
        let regs_t2 = h.list_registers().unwrap();
        let (r3_t2, pc_t2) = (regs_t2["r3"], regs_t2["pc"]);

        // Each core is preset with its own private base in r3...
        assert_eq!(r3_t1, PRIV_BASE_0, "core 0 private base");
        assert_eq!(r3_t2, PRIV_BASE_1, "core 1 private base");
        assert_ne!(r3_t1, r3_t2, "cores must have distinct private bases");

        // ...and runs its own copy of the firmware, so each pc sits in its own code
        // block (core 0 at CODE_BASE_0, core 1 at CODE_BASE_1).
        assert_eq!(
            pc_t1, CODE_BASE_0,
            "core 0 should start in its own code copy"
        );
        assert_eq!(
            pc_t2, CODE_BASE_1,
            "core 1 should start in its own code copy"
        );
    }

    /// Check breakpoint hit by non-vCPU 0.
    #[test]
    fn test_breakpoint_hits_core_1() {
        let h = harness();
        // The `stw` in core 1's *own* firmware copy lives only at this address, so
        // the breakpoint can be hit by vCPU 1.
        let stw1 = CODE_BASE_1 + PRIV_STW_OFFSET;
        h.add_breakpoint(stw1).unwrap();
        // Run round-robin until core 1 reaches its `stw`. Core 0 has no breakpoint,
        // so the only stop this can produce is core 1 hitting `stw1`.
        h.gdb_continue().unwrap();
        let stopped = h.wait_for_stop().unwrap();
        assert_eq!(stopped.address.0, stw1, "stopped at the wrong address");
        assert_eq!(
            h.current_thread().unwrap(),
            2,
            "only core 1 (thread 2) should hit core 1's breakpoint"
        );
    }

    /// Test stepi steps non-vCPU 0, keeps it current, and lets the others run.
    #[test]
    fn test_stepi_advances_core_1() {
        let h = harness();

        // Single-step with core 1 (thread 2) selected.
        h.select_thread(2).unwrap();
        let pc = h.step_instruction().unwrap();
        // A single `stepi` must advance core 1's PC by exactly one word.
        assert_eq!(
            pc,
            CODE_BASE_1 + 4,
            "stepi on core 1 should advance its PC one instruction"
        );
        // The stepped thread must remain the current/stopped thread.
        assert_eq!(
            h.current_thread().unwrap(),
            2,
            "after stepping thread 2 the stopped thread must still be thread 2"
        );
        // Check from a read register for good measure.
        h.select_thread(2).unwrap();
        assert_eq!(
            h.list_registers().unwrap()["pc"],
            CODE_BASE_1 + 4,
            "core 1's pc register should reflect its single step"
        );

        // Check tid 1 already progressed (set scheduler-locking off)
        // **technically** tid 1 can progress any amount of instructions,
        // so future gdbserver implementations may require this check
        // to change.
        h.select_thread(1).unwrap();
        assert_eq!(
            h.list_registers().unwrap()["pc"],
            CODE_BASE_0 + 4,
            "core 1's pc register should reflect its single step"
        );
    }

    /// Test both vCPUs execute and their private writes do not collide.
    #[test]
    fn test_private_writes_independent() {
        let h = harness();
        // Break on *core 1*'s private `stw`.
        // Because we run round-robin, the first breakpoint hit on vcpu 0 will not
        // have run vcpu1 yet. After continuing the second time it will be run a
        // full epoch.
        let stw1 = CODE_BASE_1 + PRIV_STW_OFFSET;
        h.add_breakpoint(stw1).unwrap();
        h.gdb_continue().unwrap();
        h.wait_for_stop().unwrap();
        h.gdb_continue().unwrap();
        h.wait_for_stop().unwrap();
        let p0 = read_u32(&h, PRIV_BASE_0);
        let p1 = read_u32(&h, PRIV_BASE_1);
        assert!(p0 > 0, "core 0 private counter should be nonzero");
        assert!(p1 > 0, "core 1 private counter should be nonzero");
    }

    /// Both vCPUs write to the shared counter.
    #[test]
    fn test_shared_counter_increments() {
        let h = harness();
        let stw0 = CODE_BASE_0 + PRIV_STW_OFFSET;
        h.add_breakpoint(stw0).unwrap();
        h.gdb_continue().unwrap();
        h.wait_for_stop().unwrap();
        let s1 = read_u32(&h, SHARED_COUNTER);
        h.gdb_continue().unwrap();
        h.wait_for_stop().unwrap();
        let s2 = read_u32(&h, SHARED_COUNTER);
        assert!(s2 > s1, "shared counter should increase: {s1} -> {s2}");
    }

    /// Test a watchpoint fires and reports the watchpoint stop reason.
    #[test]
    fn test_memory_watchpoint() {
        let h = harness();
        // Core 0 writes its private word every loop iteration, so a watchpoint on it
        // should fire quickly.
        let wp = h.add_watchpoint(PRIV_BASE_0).unwrap();
        assert!(
            h.list_watchpoints().unwrap().contains(&wp),
            "watchpoint should be registered"
        );
        h.gdb_continue().unwrap();
        let _stopped = h.wait_for_stop().unwrap();
        assert!(matches!(
            _stopped.reason.unwrap(),
            gdb_harness::StopReason::Watchpoint { number: _ }
        ));
    }
}

/// Regression test for `nexti`/`stepi` over a PowerPC `bl` (call) in the GDB plugin.
///
/// The gdb client can only recognize a `bl` as a subroutine call if it can
/// unwind the call stack, which needs (a) firmware that follows the PowerPC
/// stack conventions (the unified firmware does) and (b) function-boundary
/// symbols (loaded here from the assembled object, `FIRMWARE_OBJ_FILE`).
mod nexti {
    use super::*;
    use gdb_multicore_ppc::{
        BL_OFFSET, CODE_BASE_0, CODE_BASE_1, PRIV_BASE_0, PRIV_SUB_OFFSET, RETURN_OFFSET,
    };

    /// Load the firmware symbols, then run core 0 to its `bl` and stop there.
    /// Returns the address of the `bl`.
    fn break_at_bl(h: &GdbHarness) -> u64 {
        h.add_symbol_file(&symbol_file(), CODE_BASE_0).unwrap();
        let bl = CODE_BASE_0 + BL_OFFSET;
        h.add_breakpoint(bl).unwrap();
        h.gdb_continue().unwrap();
        let stopped = h.wait_for_stop().unwrap();
        assert_eq!(stopped.address.0, bl, "should break on the bl instruction");
        bl
    }

    /// Test `stepi` enters the callee, the contrast case for `nexti` below.
    #[test]
    fn test_stepi_steps_into_call() {
        let h = single_core_harness();
        break_at_bl(&h);

        // Sanity check for the `nexti` tests below: the firmware really does call,
        // and plain single-step lands in the callee.
        let pc = h.step_instruction().unwrap();
        assert_eq!(
            pc,
            CODE_BASE_0 + PRIV_SUB_OFFSET,
            "stepi over a `bl` should land at the subroutine entry"
        );
    }

    /// Test gdb recognizes a `bl` as a call and `nexti` runs it exactly once.
    #[test]
    fn test_nexti_steps_over_call_single_core() {
        let h = single_core_harness();
        break_at_bl(&h);

        let before = read_u32(&h, PRIV_BASE_0);
        let pc = h.next_instruction().unwrap();
        assert_eq!(
            pc,
            CODE_BASE_0 + RETURN_OFFSET,
            "nexti over a `bl` should land at the return target (call+4), not step into the subroutine \
             (got 0x{pc:x}; subroutine entry is 0x{:x})",
            CODE_BASE_0 + PRIV_SUB_OFFSET
        );
        let after = read_u32(&h, PRIV_BASE_0);
        assert_eq!(
            after,
            before + 1,
            "stepping over `bl incr_private` must run the call exactly once \
             (private counter {before} -> {after})"
        );
    }

    /// Test step works on non-vCPU 0 and each vCPU has own PC.
    #[test]
    fn test_step_reports_stepping_thread() {
        let h = dual_core_harness();

        // Step *thread 2* (core 1).
        h.select_thread(2).unwrap();
        h.step_instruction().unwrap();

        // The stepped thread must remain the current/stopped thread.
        assert_eq!(
            h.current_thread().unwrap(),
            2,
            "after stepping thread 2 the stopped thread must still be thread 2"
        );

        // Assert both cores report reasonable PCs in their firmware copies.
        h.select_thread(2).unwrap();
        let pc_t2 = h.list_registers().unwrap()["pc"];
        assert_eq!(
            pc_t2,
            CODE_BASE_1 + INSTRUCTION_SIZE,
            "core 1's PC (0x{pc_t2:x}) unexpected"
        );

        h.select_thread(1).unwrap();
        let pc_t1 = h.list_registers().unwrap()["pc"];
        assert_eq!(
            pc_t1,
            CODE_BASE_0 + INSTRUCTION_SIZE,
            "core 0's PC (0x{pc_t1:x}) unexpected"
        );
    }

    /// Test `nexti` still steps over a `bl` when other vCPUs run concurrently.
    #[test]
    fn test_nexti_steps_over_call_multi_core() {
        let h = dual_core_harness();
        // Core 1's identical `bl` sits at a different base, so it never trips core
        // 0's breakpoint. The counter check below stays deterministic because
        // `incr_private` only touches core 0's `PRIV_BASE_0`.
        break_at_bl(&h);
        assert_eq!(
            h.current_thread().unwrap(),
            1,
            "core 0 (thread 1) should hit the bl"
        );

        let before = read_u32(&h, PRIV_BASE_0);
        let pc = h.next_instruction().unwrap();
        assert_eq!(
            pc,
            CODE_BASE_0 + RETURN_OFFSET,
            "nexti over a `bl` should land at the return target (call+4), not step into the subroutine \
             (got 0x{pc:x}; subroutine entry is 0x{:x})",
            CODE_BASE_0 + PRIV_SUB_OFFSET
        );
        let after = read_u32(&h, PRIV_BASE_0);
        assert_eq!(
            after,
            before + 1,
            "stepping over core 0's `bl incr_private` must advance only core 0's \
             private counter, by one ({before} -> {after})"
        );
    }
}
