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

use crate::shadow_stack::{
    install_hooks, FrameId, FrameTransitionType, ShadowStack, ShadowStackHandle,
};
use std::collections::{HashMap, HashSet};
use std::num::NonZeroU64;
use styx_core::prelude::{
    log::{self, Level},
    *,
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
    fn new(head_addr: u64, frame_addr: u64, iters: u64, stack_depth: usize) -> Self {
        Self {
            head_addr,
            frame_addr,
            iters,
            stack_depth,
        }
    }
}

pub type LoopCallback = Box<dyn Fn(&LoopReport, &mut CoreHandle) + Send + Sync>;

#[derive(Default)]
pub struct LoopState {
    pub iterations: u64,
    pub reported: bool,
}

pub struct LoopCounters {
    pub threshold: u64,
    pub counters: HashMap<FrameId, HashMap<u64, LoopState>>,
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
                    Some(LoopReport::new(
                        target,
                        frame.entry_addr,
                        state.iterations,
                        depth,
                    ))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Drop counters for frames no longer on the stack.
    pub fn remove_loops(&mut self, stack: &ShadowStack) {
        let live: HashSet<FrameId> = stack.frames().iter().map(|f| f.id).collect();
        self.counters.retain(|id, _| live.contains(id));
    }
}

#[derive(Default)]
struct DetectionBehavior {
    /// Halt emulation
    halt: bool,
    /// Invokes user callback function
    callback: Option<LoopCallback>,
    /// Log at given level
    log: Option<Level>,
    /// Error with message
    err: Option<String>,
}

struct LoopDetector {
    handle: ShadowStackHandle,
    counters: LoopCounters,
    on_detection: Arc<DetectionBehavior>,
}

impl LoopDetector {
    fn new(
        handle: ShadowStackHandle,
        threshold: u64,
        on_detection: Arc<DetectionBehavior>,
    ) -> Self {
        Self {
            handle,
            counters: LoopCounters::new(threshold),
            on_detection,
        }
    }

    fn report_loop(
        &mut self,
        report: &LoopReport,
        proc: &mut CoreHandle,
    ) -> Result<(), UnknownError> {
        if let Some(level) = self.on_detection.log {
            log::log!(
                level,
                "LoopDetectionPlugin: vcpu {} loop @ {:#x} in frame {:#x} (call depth {}) reached {} iterations",
                proc.vcpu_id(), report.head_addr, report.frame_addr, report.stack_depth, report.iters
            );
        }
        if let Some(callback) = self.on_detection.callback.as_ref() {
            callback(report, proc);
        }
        if self.on_detection.halt {
            proc.cpu.stop();
        }
        if let Some(err_msg) = &self.on_detection.err {
            return Err(anyhow!(
                "LoopDetectionPlugin: vcpu {}: {err_msg}",
                proc.vcpu_id()
            ));
        }
        Ok(())
    }
}

impl BlockHook for LoopDetector {
    fn call(
        &mut self,
        mut proc: CoreHandle,
        _address: u64,
        _size: u32,
    ) -> Result<(), UnknownError> {
        let report = self.handle.read(|stack| self.counters.observe_stack(stack));
        if let Some(report) = report {
            self.report_loop(&report, &mut proc)?;
        }
        Ok(())
    }
}

#[derive(serde::Deserialize)]
pub struct LoopDetectionPlugin {
    /// Number of iterations of the loop before it's reported
    /// Minimum threshold = 1
    threshold: NonZeroU64,
    /// If true, stop the reporting vcpu when loop is reported
    #[serde(default)]
    halt_on_report: bool,
    /// Invoked when loop is reported
    #[serde(skip)]
    on_report: Option<LoopCallback>,
    /// Optional logging; if set, log each report at this level
    #[serde(skip)]
    log_level: Option<Level>,
    /// If set, the hook fails with this error message when a loop is reported
    #[serde(default)]
    err_on_report: Option<String>,
    /// One handle per vcpu, indexed by vcpu id
    #[serde(skip)]
    shadow_stacks: Option<Vec<ShadowStackHandle>>,
}

impl Default for LoopDetectionPlugin {
    fn default() -> Self {
        Self {
            threshold: NonZeroU64::new(1).unwrap(),
            halt_on_report: false,
            on_report: None,
            log_level: Some(Level::Info),
            err_on_report: None,
            shadow_stacks: None,
        }
    }
}

styx_uconf::register_component_config!(register plugin: id = loops, component = LoopDetectionPlugin);

impl LoopDetectionPlugin {
    pub fn with_threshold(mut self, threshold: u64) -> Self {
        self.threshold = NonZeroU64::new(threshold).unwrap();
        self
    }

    pub fn with_halt_on_report(mut self, halt_on_report: bool) -> Self {
        self.halt_on_report = halt_on_report;
        self
    }

    pub fn with_callback(mut self, callback: LoopCallback) -> Self {
        self.on_report = Some(callback);
        self
    }

    pub fn with_log_level(mut self, level: Option<Level>) -> Self {
        self.log_level = level;
        self
    }

    pub fn with_err(mut self, message: impl Into<String>) -> Self {
        self.err_on_report = Some(message.into());
        self
    }

    pub fn with_shadow_stacks(mut self, shadow_stacks: Vec<ShadowStackHandle>) -> Self {
        self.shadow_stacks = Some(shadow_stacks);
        self
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
        let handles = match self.shadow_stacks.take() {
            Some(handles) => {
                if handles.len() != proc.vcpus.len() {
                    return Err(anyhow!(
                        "LoopDetectionPlugin: got {} shadow stacks for {} vcpus",
                        handles.len(),
                        proc.vcpus.len()
                    ));
                }
                if handles.iter().any(|handle| !handle.has_updater()) {
                    return Err(anyhow!(
                        "LoopDetectionPlugin: a provided shadow stack does not have an updater.\
                        Add the ShadowStackPlugin before the LoopDetectionPlugin"
                    ));
                }
                handles
            }
            None => {
                let handles: Vec<_> = (0..proc.vcpus.len())
                    .map(|_| ShadowStackHandle::new())
                    .collect();
                install_hooks(proc, &handles)?;
                handles
            }
        };
        // shared so a single user callback/halt/err covers every vcpu
        let behavior = Arc::new(DetectionBehavior {
            halt: self.halt_on_report,
            callback: self.on_report.take(),
            log: self.log_level,
            err: self.err_on_report.take(),
        });
        for (vcpu, handle) in proc.vcpus.iter_mut().zip(handles) {
            let reader = LoopDetector::new(handle, self.threshold.get(), behavior.clone());
            vcpu.cpu.add_hook(StyxHook::block(reader))?;
        }
        Ok(self)
    }
}
