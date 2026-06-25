// SPDX-License-Identifier: BSD-2-Clause

//! This plugin maintains a shadow stack that approximates the actual call stack.
//! 
//! This plugin installs a block hook that classifies the last instruction of the
//! basic block ([`ControlFlowType`]). We then use this classification to determine
//! if we need to push ([`ControlFlowType::Call`]) or pop a frame
//! ([`ControlFlowType::Return`]). Users and other plugins can read this shadow stack
//! via a handle.
//! 
//! Currently, this plugin only works for the PCode backend as we need to be able to
//! classify the last instruction of a basic block (is it a call, return, branch, etc)
//! to update the shadow stack. It can be extended for the Unicorn backend, but
//! we'd have to deal with architecture-specfic stuff. 
//! 
//! The initial motivation for this plugin was so that the loop detector plugin
//! could determine what stack frame the state was currently in, and this
//! technique of getting a view into the call stack is more robust and
//! architecture-agnostic than using the stack and frame pointers. However, there are
//! certain operations that can desync the shadow stack to the actual call stack.
//! For example, `longjmp`s or obfuscated code. This current version just accounts for
//! static `call` and `return`, but additional measures can be added upon further
//! research to harden the shadow stack.

use styx_core::prelude::*;
use styx_sync::sync::{Arc, Mutex};
use tracing::warn;

pub type FrameId = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    /// Unique id for this activation.
    pub id: FrameId,
    /// The address at which this activation was entered.
    pub entry_addr: u64,
    /// Expected return address when frame is popped.
    pub return_addr: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameTransitionType {
    /// First observed block
    Start { target: u64 },
    /// A call pushed a new frame; `target` is the callee entry.
    Call { source: u64, target: u64 },
    /// A return popped back to `target`.
    Return { target: u64 },
    /// An edge within the current frame.
    Branch { source: u64, target: u64 },
}

/// State about the basic block we are currently in. This is used to inform
/// if we should push or pop a frame for the next block if this pending block's
/// exit instruction was a call/return.
#[derive(Clone, Copy)]
struct PendingBlock {
    addr: u64,
    /// address right after this block
    fallthrough_addr: u64,
    exit_flow_type: ControlFlowType,
    /// static target of a direct call/branch terminator
    target: Option<u64>,
}

#[derive(Default)]
pub struct ShadowStack {
    frames: Vec<Frame>,
    next_id: FrameId,
    prev_trans: Option<FrameTransitionType>,
    pending: Option<PendingBlock>,
    has_updater: bool,
}

impl ShadowStack {
    pub fn depth(&self) -> usize {
        self.frames.len()
    }

    /// The top frame
    pub fn top(&self) -> Option<Frame> {
        self.frames.last().copied()
    }

    /// Bottom of the stack first
    pub fn frames(&self) -> &[Frame] {
        &self.frames
    }

    /// Bottom of the stack to the top
    pub fn bottom_to_top_iter(&self) -> impl Iterator<Item = &Frame> {
        self.frames.iter().rev()
    }

    pub fn prev_transition(&self) -> Option<FrameTransitionType> {
        self.prev_trans
    }

    /// Checks if a hook responsible for updating this stack has been registered.
    /// 
    /// Other plugins use this to enforce wiring order: the updater hook must be
    /// registered before any downstream plugin, so its block hook runs first.
    pub fn has_updater(&self) -> bool {
        self.has_updater
    }

    pub fn set_updater(&mut self) {
        self.has_updater = true;
    }

    /// Called upon entry into basic block
    pub fn record_block(&mut self, addr: u64, size: u32, flow: ControlFlowType) {
        self.record_block_with_target(addr, size, flow, None);
    }

    /// Same as [`Self::record_block`]`, except target is the statically-known direct call/branch
    /// destination
    pub fn record_block_with_target(
        &mut self,
        addr: u64,
        size: u32,
        flow: ControlFlowType,
        target: Option<u64>,
    ) {
        let transition = match self.pending {
            None => {
                // First block. No meaningful return address so we just set it 0
                self.push_frame(addr, 0);
                FrameTransitionType::Start { target: addr }
            }
            Some(prev) => self.apply_edge(prev, addr),
        };
        self.prev_trans = Some(transition);
        self.pending = Some(PendingBlock {
            addr,
            fallthrough_addr: addr + (size as u64),
            exit_flow_type: flow,
            target,
        });
    }

    fn apply_edge(&mut self, prev: PendingBlock, curr: u64) -> FrameTransitionType {
        match prev.exit_flow_type {
            ControlFlowType::Call => {
                // Verifying if a conditional call was taken. If not, we treat
                // it as a branch. Otherwise, the call was taken and we push a
                // frame. For now, we don't check indirect calls.
                if prev.target.is_some_and(|target| target != curr) {
                    FrameTransitionType::Branch {
                        source: prev.addr,
                        target: curr,
                    }
                } else {
                    // We assume that the return address is the instruction immediately after the call, since it's the common case; perhaps make it more robust?
                    // Making it more robust would mean reading the return address the call actually pushed (from the stack or LR)
                    self.push_frame(curr, prev.fallthrough_addr);
                    FrameTransitionType::Call {
                        source: prev.addr,
                        target: curr,
                    }
                }
            }
            ControlFlowType::Return => {
                self.pop_to(curr);
                FrameTransitionType::Return { target: curr }
            }
            ControlFlowType::Branch | ControlFlowType::Fallthrough | ControlFlowType::Unknown => {
                FrameTransitionType::Branch {
                    source: prev.addr,
                    target: curr,
                }
            }
        }
    }

    fn push_frame(&mut self, entry_addr: u64, return_addr: u64) {
        let id = self.next_id;
        self.next_id += 1;
        self.frames.push(Frame {
            id,
            entry_addr,
            return_addr,
        });
    }

    /// Pop the frame until we land at curr
    /// 
    /// Cleanest case is `curr` matching the top frame's recorded return address
    /// 
    /// However, sometimes it won't due to a variety of reasons (tail calls, longjmp,
    /// interrupt returns, etc.). This will desync the shadow stack. We resync it by
    /// popping to the frame that was expecting `curr`.
    /// 
    /// We don't pop out the initial frame
    fn pop_to(&mut self, curr: u64) {
        if self.frames.len() <= 1 {
            return;
        }
        match self.frames.iter().rposition(|f| f.return_addr == curr) {
            Some(idx) if idx >= 1 => self.frames.truncate(idx),
            _ => {
                self.frames.pop();
            }
        }
    }
}

/// Handle to a [`ShadowStack`]
#[derive(Clone, Default)]
pub struct ShadowStackHandle(Arc<Mutex<ShadowStack>>);

impl ShadowStackHandle {
    pub fn new() -> Self {
        Self::default()
    }

    // Read the state of the shadow stack with a function
    pub fn read<R>(&self, f: impl FnOnce(&ShadowStack) -> R) -> R {
        f(&mut self.0.lock().unwrap())
    }

    // Apply a function to a mutable view of the underlying shadow stack. Only visible to this crate
    pub(crate) fn update<R>(&self, f: impl FnOnce(&mut ShadowStack) -> R) -> R {
        f(&mut self.0.lock().unwrap())
    }

    pub fn depth(&self) -> usize {
        self.0.lock().unwrap().depth()
    }

    pub fn top(&self) -> Option<Frame> {
        self.0.lock().unwrap().top()
    }

    /// Bottom of the stack to the top
    pub fn bottom_to_top(&self) -> Vec<Frame> {
        self.0.lock().unwrap().bottom_to_top_iter().copied().collect()
    }

    pub fn has_updater(&self) -> bool {
        self.0.lock().unwrap().has_updater
    }
}


// Install block hook and sets `has_updater` variable to true so donwstream handles
// know that this shadow stack has an updater
pub(crate) fn install_hook(
    proc: &mut BuildingProcessor,
    handle: &ShadowStackHandle,
) -> Result<(), UnknownError> {
    let hook_handle = handle.clone();
    let mut warned_weird_state = false;
    proc.core
        .cpu
        .add_hook(StyxHook::block(move |core: CoreHandle, address, size| {
            let term =
                classify_block_terminator(core.cpu, address, size, core.mmu, core.event_controller);
            if (term.is_none() || term.unwrap().flow == ControlFlowType::Unknown) && !warned_weird_state {
                warn!(
                    "ShadowStack: backend cannot classify control flow; \
                    the shadow stack might get weird man!"
                );
                warned_weird_state = true;
            }
            hook_handle.update(|stack| {
                // defaulting is OK because we've warned the user that the state would get weird
                stack.record_block_with_target(address, size, term.unwrap_or_default().flow, term.unwrap_or_default().target)
            });
            Ok(())
        }))?;
    handle.update(|s| s.set_updater());
    Ok(())
}

/// Plugin for the [`ShadowStack`]. Other plugins/tasks can use the [`Self::handle`]
/// to read the shadow stack
/// 
/// Add this plugin before any other plugin that uses the shadow stack, so the updater
/// hook runs first on each basic block
#[derive(Default, serde::Deserialize)]
pub struct ShadowStackPlugin {
    #[serde(skip)]
    handle: ShadowStackHandle,
}

styx_uconf::register_component_config!(register plugin: id = shadow_stack, component = ShadowStackPlugin);

impl ShadowStackPlugin {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clone_handle(&self) -> ShadowStackHandle {
        self.handle.clone()
    }
}

impl Plugin for ShadowStackPlugin {
    fn name(&self) -> &str {
        "Shadow Stack"
    }
}

impl UninitPlugin for ShadowStackPlugin {
    fn init(
        self: Box<Self>,
        proc: &mut BuildingProcessor,
    ) -> Result<Box<dyn Plugin>, UnknownError> {
        install_hook(proc, &self.handle)?;
        Ok(self)
    }
}


