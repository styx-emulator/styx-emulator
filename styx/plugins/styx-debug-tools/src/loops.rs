// SPDX-License-Identifier: BSD-2-Clause

//! Loop detection plugin built on top of the [shadow stack](crate::shadow_stack) plugin.
//! 
//! Based on the paper: [LoopProf: Dynamic Techniques for Loop Detection and Profiling](<https://www.researchgate.net/profile/Daniel-Connors-2/publication/249981892_LoopProf_Dynamic_Techniques_for_Loop_Detection_and_Profiling/links/547eb6da0cf2d2200ede9d06/LoopProf-Dynamic-Techniques-for-Loop-Detection-and-Profiling.pdf>)
//! 
//! This plugin reports a loop once it has been iterated through at least a user-provided
//! number of times. Unlike the paper, this plugin collects no profiling information: it
//! only detects and reports loops. Profiling information can be added in the future, but
//! it would have to be a configurable feature because collecting profiling information
//! will dramatically slow down the speed of the emulator.

use std::collections::{HashMap, HashSet};
use styx_core::prelude::{log::info, *};
use crate::shadow_stack::{
    install_hook, FrameId, FrameTransitionType, ShadowStack, ShadowStackHandle,
};

/// Report on loop that has been detected and has been iterated over by the user
/// specified threshold.
#[derive(Debug, Clone, Copy)]
pub struct LoopReport {
    /// Address of the loop header
    pub head_addr: u64,
    /// Entry address of the stack frame the loop belongs to
    pub frame_addr: u64,
    /// Number of times the loop has been iterated over
    pub iters: u64,
    pub stack_depth: usize,
}

impl LoopReport {
    pub fn new(head_addr: u64, frame_addr: u64, iters: u64, stack_depth: usize) -> Self {
        Self {
            head_addr,
            frame_addr,
            iters,
            stack_depth
        }
    }
}

pub type LoopCallback = Box<dyn FnMut(&LoopReport) + Send>;

#[derive(Default)]
struct LoopState {
    iterations: u64,
    reported: bool,
}

#[derive(Default)]
pub struct LoopCounters {
    threshold: u64,
    counters: HashMap<FrameId, HashMap<u64, LoopState>>,
}

impl LoopCounters {
    pub fn new(threshold: u64) -> Self {
        Self {
            threshold,
            counters: HashMap::new(),
        }
    }

    /// Observed the shadow stack to see if we need to update the LoopCounters
    /// state and/or if we need to report a loop
    // clippy suggests the `Entry` API here; we prefer the explicit
    // contains/insert form for readability.
    #[allow(clippy::map_entry)]
    pub fn observe_stack(&mut self, stack: &ShadowStack) -> Option<LoopReport> {
        match stack.prev_transition()? {
            // A frame just returned; drop counters for loops that are gone.
            FrameTransitionType::Return { .. } => {
                self.remove_loops(stack);
                None
            }
            FrameTransitionType::Branch { source, target } if target <= source => {
                let frame = stack.top()?;
                let depth = stack.depth();

                if !self.counters.contains_key(&frame.id) {
                    self.counters.insert(frame.id, HashMap::new());
                }
                let loops = self.counters.get_mut(&frame.id).unwrap();

                if !loops.contains_key(&target) {
                    loops.insert(target, LoopState::default());
                }
                let state = loops.get_mut(&target).unwrap();

                state.iterations += 1;
                if !state.reported && state.iterations >= self.threshold {
                    state.reported = true;
                    Some(LoopReport::new(target, frame.entry_addr,state.iterations,depth))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Drop counters for frames no longer on the stack.
    fn remove_loops(&mut self, stack: &ShadowStack) {
        let live: HashSet<FrameId> = stack.frames().iter().map(|f| f.id).collect();
        self.counters.retain(|id, _| live.contains(id));
    }
}

struct LoopDetector {
    handle: ShadowStackHandle,
    counters: LoopCounters,
    halt_on_detection: bool,
    on_detection: Option<LoopCallback>,
}

impl LoopDetector {
    fn new(
        handle: ShadowStackHandle,
        threshold: u64,
        halt_on_detection: bool,
        on_detection: Option<LoopCallback>,
    ) -> Self {
        Self {
            handle,
            counters: LoopCounters::new(threshold),
            halt_on_detection,
            on_detection,
        }
    }

    fn report_loop(&mut self, report: &LoopReport, proc: &mut CoreHandle) {
        info!(
            "LoopDetectionPlugin: loop @ {:#x} in frame {:#x} (call depth {}) reached {} iterations",
            report.head_addr, report.frame_addr, report.stack_depth, report.iters
        );
        if let Some(callback) = self.on_detection.as_mut() {
            callback(report);
        }
        if self.halt_on_detection {
            proc.cpu.stop();
        }
    }
}

impl BlockHook for LoopDetector {
    fn call(&mut self, mut proc: CoreHandle, _address: u64, _size: u32) -> Result<(), UnknownError> {
        let report = self.handle.read(|stack| self.counters.observe_stack(stack));
        if let Some(report) = report {
            self.report_loop(&report, &mut proc);
        }
        Ok(())
    }
}

#[derive(Default, serde::Deserialize)]
pub struct LoopDetectionPlugin {
    /// Number of iterations of the loop before it's reported
    threshold: u64,
    /// If true, stop emulation when loop is reported
    #[serde(default)]
    halt_on_report: bool,
    /// Invoked when loop is reported
    #[serde(skip)]
    on_report: Option<LoopCallback>,
    #[serde(skip)]
    shadow_stack: Option<ShadowStackHandle>,
}

styx_uconf::register_component_config!(register plugin: id = loops, component = LoopDetectionPlugin);

impl LoopDetectionPlugin {
    pub fn new(threshold: u64, halt_on_detection: bool, on_detection: Option<LoopCallback>, shadow_stack: Option<ShadowStackHandle>) -> Self {
        Self {
            threshold,
            halt_on_report: halt_on_detection,
            on_report: on_detection,
            shadow_stack
        }
    }
}

impl Plugin for LoopDetectionPlugin {
    fn name(&self) -> &str {
        "LoopDetection"
    }
}

impl UninitPlugin for LoopDetectionPlugin {
    fn init(
        mut self: Box<Self>,
        proc: &mut BuildingProcessor,
    ) -> Result<Box<dyn Plugin>, UnknownError> {
        let handle = match self.shadow_stack.take() {
            Some(handle) => {
                if !handle.has_updater() {
                    return Err(anyhow!(
                        "LoopDetectionPlugin: the provided shadow stack does not have an updater.\
                        Add the ShadowStackPlugin before the LoopDetectionPlugin"
                    ));
                }
                handle
            }
            None => {
                let handle = ShadowStackHandle::new();
                install_hook(proc, &handle)?;
                handle
            }
        };
        // minimum threshold value is 1
        let reader = LoopDetector::new(
            handle,
            self.threshold.max(1),
            self.halt_on_report,
            self.on_report.take(),
        );
        proc.core.cpu.add_hook(StyxHook::block(reader))?;
        Ok(self)
    }
}




