// SPDX-License-Identifier: BSD-2-Clause

use styx_core::cpu::ControlFlowType;
use styx_debug_tools::{ShadowStack, FrameTransitionType};

#[test]
fn call_pushes_and_return_pops() {
    let mut s = ShadowStack::default();

    // first block seeds the base frame
    s.record_block(0x10, 4, ControlFlowType::Call);
    assert_eq!(s.depth(), 1);
    assert_eq!(s.prev_transition(), Some(FrameTransitionType::Start { target: 0x10 }));

    // the call (0x10 -> 0x100) pushes a callee frame
    s.record_block(0x100, 4, ControlFlowType::Return);
    assert_eq!(s.depth(), 2);
    assert!(matches!(
        s.prev_transition(),
        Some(FrameTransitionType::Call { target: 0x100, .. })
    ));
    assert_eq!(s.top().unwrap().entry_addr, 0x100);

    // the return lands back at 0x14 and pops the callee
    s.record_block(0x14, 4, ControlFlowType::Branch);
    assert_eq!(s.depth(), 1);
    assert_eq!(s.prev_transition(), Some(FrameTransitionType::Return { target: 0x14 }));
    assert_eq!(s.top().unwrap().entry_addr, 0x10);
}

#[test]
fn return_resyncs_to_matching_frame() {
    let mut s = ShadowStack::default();
    s.record_block(0x10, 4, ControlFlowType::Call); // base frame, call ret addr 0x14
    s.record_block(0x100, 4, ControlFlowType::Call); // push callee, call ret addr 0x104
    s.record_block(0x200, 4, ControlFlowType::Return); // push inner callee
    assert_eq!(s.depth(), 3);

    // a return landing at 0x14 unwinds past the inner frames to the one that
    // expected 0x14
    s.record_block(0x14, 4, ControlFlowType::Branch);
    assert_eq!(s.depth(), 1);
    assert_eq!(s.top().unwrap().entry_addr, 0x10);
}

#[test]
fn updater_registration_flag() {
    let mut s = ShadowStack::default();
    assert!(!s.has_updater());
    s.set_updater();
    assert!(s.has_updater());
}

#[test]
fn recursion_yields_distinct_frame_ids() {
    let mut s = ShadowStack::default();
    s.record_block(0x10, 4, ControlFlowType::Call); // base
    s.record_block(0x100, 4, ControlFlowType::Call); // first activation of 0x100
    let first = s.top().unwrap().id;
    s.record_block(0x100, 4, ControlFlowType::Return); // recursive call into 0x100
    let second = s.top().unwrap().id;
    assert_ne!(first, second, "each activation gets a unique id");
    assert_eq!(s.depth(), 3);
}

#[test]
fn untaken_direct_call_does_not_push() {
    let mut s = ShadowStack::default();
    // a block whose terminator is a direct call to 0x500 (e.g. a conditional
    // `blne 0x500`)...
    s.record_block_with_target(0x100, 0x10, ControlFlowType::Call, Some(0x500));
    // ...but control next lands at 0x120, not 0x500; the call fell through and
    // a later branch brought us here. The call was not taken
    s.record_block_with_target(0x120, 0x10, ControlFlowType::Branch, None);
    assert_eq!(s.depth(), 1, "an untaken call must not push a frame");
    assert!(matches!(
        s.prev_transition(),
        Some(FrameTransitionType::Branch { target: 0x120, .. })
    ));
}

#[test]
fn taken_direct_call_pushes_when_target_matches() {
    let mut s = ShadowStack::default();
    s.record_block_with_target(0x100, 0x10, ControlFlowType::Call, Some(0x500));
    // control lands exactly at the call's target; the call was taken
    s.record_block_with_target(0x500, 0x10, ControlFlowType::Branch, None);
    assert_eq!(s.depth(), 2, "a taken call pushes a frame");
    assert_eq!(s.top().unwrap().entry_addr, 0x500);
}

#[test]
fn indirect_call_pushes_without_target() {
    let mut s = ShadowStack::default();
    // an indirect call has no static target, so it's taken at face value
    s.record_block_with_target(0x100, 0x10, ControlFlowType::Call, None);
    s.record_block_with_target(0x900, 0x10, ControlFlowType::Branch, None);
    assert_eq!(s.depth(), 2, "an indirect call (no known target) still pushes");
    assert_eq!(s.top().unwrap().entry_addr, 0x900);
}




