// SPDX-License-Identifier: BSD-2-Clause

use styx_core::cpu::ControlFlowType;
use styx_debug_tools::{LoopCounters, LoopReport, ShadowStack};

// a synthetic basic block: (start address, size in bytes, terminator type)
type Block = (u64, u32, ControlFlowType);

// drive a sequence of block entries through a shadow stack and the detector's
// pure core, collecting any reports
fn run(threshold: u64, blocks: &[Block]) -> Vec<LoopReport> {
    let mut stack = ShadowStack::default();
    let mut counters = LoopCounters::new(threshold);
    let mut reports = Vec::new();
    for &(addr, size, flow) in blocks {
        stack.record_block(addr, size, flow);
        if let Some(report) = counters.observe_stack(&stack) {
            reports.push(report);
        }
    }
    reports
}

#[test]
fn simple_loop_reaches_threshold() {
    let mut blocks: Vec<Block> = vec![(0x100, 0x10, ControlFlowType::Branch)];
    for _ in 0..5 {
        blocks.push((0x110, 0x10, ControlFlowType::Branch));
        blocks.push((0x100, 0x10, ControlFlowType::Branch));
    }
    let reports = run(3, &blocks);
    assert_eq!(reports.len(), 1, "loop should be reported exactly once");
    assert_eq!(reports[0].head_addr, 0x100);
    assert_eq!(reports[0].iters, 3);
    assert_eq!(reports[0].stack_depth, 1);
}

#[test]
fn loop_below_threshold_is_silent() {
    let mut blocks: Vec<Block> = vec![(0x100, 0x10, ControlFlowType::Branch)];
    for _ in 0..2 {
        blocks.push((0x110, 0x10, ControlFlowType::Branch));
        blocks.push((0x100, 0x10, ControlFlowType::Branch));
    }
    assert!(run(5, &blocks).is_empty());
}

// the key correctness case: calling a function whose entry (0x100) lies
// below the call site (0x200) must NOT be mistaken for a loop back-edge,
// because the shadow stack reports the edge as a `Call`
#[test]
fn call_to_lower_address_is_not_a_loop() {
    let blocks: &[Block] = &[
        (0x200, 0x4, ControlFlowType::Call),
        (0x100, 0x4, ControlFlowType::Return),
        (0x204, 0x4, ControlFlowType::Branch),
    ];
    assert!(
        run(1, blocks).is_empty(),
        "a call to a lower address must not register as a loop"
    );
}

// a loop inside a callee is attributed to the callee's frame (depth 2)
#[test]
fn loop_inside_callee_is_detected() {
    let mut blocks: Vec<Block> = vec![
        (0x200, 0x4, ControlFlowType::Call),
        (0x100, 0x10, ControlFlowType::Branch),
    ];
    for _ in 0..4 {
        blocks.push((0x110, 0x10, ControlFlowType::Branch));
        blocks.push((0x100, 0x10, ControlFlowType::Branch));
    }
    let reports = run(3, &blocks);
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].head_addr, 0x100);
    assert_eq!(reports[0].frame_addr, 0x100, "loop belongs to the callee");
    assert_eq!(reports[0].stack_depth, 2);
}

// after a callee returns, a loop in the caller is attributed to the caller
// (depth 1)
//
// verifying the return popped the callee frame
#[test]
fn return_pops_to_caller_frame() {
    let mut blocks: Vec<Block> = vec![
        (0x10, 0x4, ControlFlowType::Call),
        (0x100, 0x4, ControlFlowType::Return),
        (0x14, 0x10, ControlFlowType::Branch),
    ];
    for _ in 0..3 {
        blocks.push((0x24, 0x10, ControlFlowType::Branch));
        blocks.push((0x14, 0x10, ControlFlowType::Branch));
    }
    let reports = run(3, &blocks);
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].head_addr, 0x14);
    assert_eq!(reports[0].stack_depth, 1);
}

// without classification (every terminator `Unknown`), the shadow stack stays
// single-framed and the back-edge heuristic alone applies, so the call to a
// lower address is (incorrectly) reported
// 
// documents the degraded-mode behavior
#[test]
fn unknown_classification_degrades_to_backedge_only() {
    let blocks: &[Block] = &[
        (0x200, 0x4, ControlFlowType::Unknown),
        (0x100, 0x4, ControlFlowType::Unknown),
    ];
    let reports = run(1, blocks);
    assert_eq!(
        reports.len(),
        1,
        "degraded mode treats the call as a back-edge"
    );
    assert_eq!(reports[0].head_addr, 0x100);
}



