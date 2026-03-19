// SPDX-License-Identifier: BSD-2-Clause
//! Defines [`TargetImpl`] and implements gdbstub `Target` traits for multi-thread debugging.
//!
//! [`TargetImpl`] sits between [`gdbstub`] and the [`CpuBackend`]
//! to control cpu execution and the various `gdbstub` trait implementations
//! found in this module.
//!
//! The [`TargetImpl`] traits are essentially a collection of handlers invoked by the _gdb
//! client_ over the gdb serial protocol. The gdbstub uses a technique called
//! _Inlineable Dynamic Extension Traits_ (_IDETs_) to expose the interface
//! to the GDB protocol.
//!
//! See
//! [_Implementing Target_](https://docs.rs/gdbstub/0.7.3/gdbstub/target/index.html#implementing-target)
//! for an explanation, see `support_breakpoints` in the source for an example.
//!
//! There is also discussion
//! [`here`](https://github.com/daniel5151/inlinable-dyn-extension-traits/blob/master/writeup.md)
//!
//! ## Multiprocessor Considerations
//! gdbstub contains a sister set of target extensions for multithread
//! specifically in `gdbstub::target::ext::base`.
//!
//! We represent each vcpu as a gdb thread (`Tid`). The mapping can be found
//! in [`super::event_loop::index_to_tid()`]. The mapping is simple, just
//! that `Tid`'s are 1 indexed. In this crate thread and vcpu core will be used
//! interchangeably.
//!
//! When breaking a single thread we must consider what happens to the other threads.
//! The default mode in gdb (and the only supported mode in gdbstub) is **all-stop mode**.
//! As you may be able to guess, when a threads stops in all-stop mode, all the other
//! threads stop with it.
//!
//! Documentation for all-stop mode can be found at <https://sourceware.org/gdb/current/onlinedocs/gdb.html/All_002dStop-Mode.html>.
//!
//! When a thread is resumed in all-stop mode, all other threads should continue until a thread stops again, either because
//! it was stepped or it hit another breakpoint.
//!
//! In styx, we simplify a little bit. Since we execute round robin style,
//! the other threads are not being executed in parallel. Instead, if any thread is stepping
//! then we step all other threads as well (instead of continuing).
//!
//! ## Scheduler Locking
//! **NOTE**: According to GDB, thread behavior on resume should determined by
//! the `scheduler-locking` option. Styx's gdbserver implements the required
//! gdbstub trait (MultiThreadSchedulerLocking) but this silently does nothing.
//! We implement this because gdbstub's behavior is to fatally error if gdb
//! sets `scheduler-lock on` if the `TargetImpl` doesn't implement
//! `MultiThreadSchedulerLocking`.
//!
//! A real implementation of `MultiThreadSchedulerLocking` would set scheduler
//! locking on/off. Scheduler locking off means that any thread can run at any time.
//! This is the styx gdb server behavior. Scheduler locking on means that only the
//! current thread may run whening stepping, next, continue, etc.
//!
use crate::{
    event_loop::{self, index_to_tid, tid_to_index, RunEvent},
    mem_watch::Watchpoints,
    GDBOptions, StepIRQs,
};
use gdbstub::{
    common::{Signal, Tid},
    target::{
        self,
        ext::breakpoints::{HwWatchpointOps, SwBreakpointOps, WatchKind},
        TargetError, TargetResult,
    },
};
use itertools::Itertools;
use num_traits::{FromPrimitive, ToPrimitive};
use std::{collections::BTreeMap, marker::PhantomData, time::Instant};
use styx_core::{
    arch::ArchitectureDef,
    core::VcpuCore,
    cpu::{
        arch::{CpuRegister, GdbRegistersHelper},
        ArchEndian, TargetExitReason,
    },
    executor::time::GlobalDelta,
    hooks::CodeHook,
    plugins::Plugins,
};
use styx_core::{executor::time::VcpuTime, prelude::*};
use tracing::{debug, error, info, trace, warn};

use super::breakpoint_manager::BreakpointManager;

/// This method is called via target emulation hooks when a code breakpoint
/// is hit via target software.
///
/// This hook / proxy method is the real meat behind "gdb plugin go fast",
/// and is how we avoid needing to single step.
///
/// By working off of a shared [`BreakpointManager`], we are able to control
/// the behavior and reception of events and gdb interrupts.
///
/// When a breakpoint is first hit, `bp_state.paused` == `false`, so
/// we then set the paused flag and stop the cpu. This then redirects
/// control flow back to [`TargetImpl`] so it can process any applicable
/// commands or events before continuing execution.
///
/// This process continues ad infinium.
struct GdbBreakpointHook(Arc<BreakpointManager>);
impl CodeHook for GdbBreakpointHook {
    fn call(&mut self, proc: CoreHandle) -> Result<(), UnknownError> {
        let vcpu_idx = proc.vcpu_id();
        let pc = proc.cpu.pc().unwrap();
        // check if pc is in our breakpoints, if not then bail
        if !self.0.contains_active(&pc) {
            trace!("HOOK: `0x{pc:08x}` is not in active breakpoints");
            return Ok(());
        }
        debug!("HOOK: pc@{pc:08x} active breakpoint (vcpu {vcpu_idx})");
        // At some point gdb used to continue on the same PC, trigger
        // the code hook here. To restrict breakpoints from accidentally
        // firing twice here, we used to detect that this is the old breakpoint
        // and unpause and continue. As of now, gdb  seems to mitigate this
        // by disabling the breakpoint, stepping, reenabling the breakpoint
        // and then finally continuing, avoiding the problem all together.
        //
        // We need to pause self and stop the cpu. once the cpu is stopped, then
        // the control flow in `self.resume` will continue, and the breakpoint
        // event will be propagated because `self.paused` is now set
        self.0.pause_with_vcpu(pc, vcpu_idx);
        proc.cpu.stop();
        Ok(())
    }
}

/// Track the current gdb execution mode - used let the event loop
/// know that we want to resume target (emulator) execution
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecMode {
    /// Resume cpu until an [`Event`](super::event_loop::Event)
    Continue,
    /// Step range, where the ranges are addresses (for example,
    /// `(gdb) step 0xfa 0xff`), note that these are stored as [`u64`],
    /// because styx-backends represent all addresses as [`u64`]
    RangeStep(u64, u64),
    /// Resume cpu for 1 step
    Step,
}

/// Holds the state of the target emulation session
///
/// In order to be able to implement a debug target manager
/// for multiple architecture targets, this definition is
/// generic across the specific underlying metadata information,
/// as [`gdbstub`] requires that *each* target be monomorphized
/// for *exactly 1* gdb target architecture.
///
/// Due to the lack of const support at the trait level, we have
/// many automatically generated structs and traits that are used
/// to assist developers in creating the support infrastructure
/// necessary to utilize [`gdbstub`] (it is not the best solution,
/// but the quickest)
/// TODO: fix this situation
pub(crate) struct TargetImpl<'a, GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    pub(crate) vcpus: &'a mut PerVcpuSlice<VcpuCore>,
    pub(crate) core: &'a mut ProcessorCore,
    /// Plugin collection, ticked once per global round (see
    /// [`Self::global_round_tick`]).
    pub(crate) plugins: &'a mut Plugins,
    /// Per-vCPU execution mode, keyed by GDB Tid.
    pub(crate) resume_actions: BTreeMap<Tid, ExecMode>,
    /// The emulator's core register size in bits (eg: 32 or 64)
    pub(crate) reg_size: usize,
    /// Used to check if we are paused in a breakpoint etc. or not
    breakpoint_state: Arc<BreakpointManager>,
    /// Memory-write watchpoints requested by the gdb client. Owns the per-vCPU
    /// hook tokens and the set of watched addresses; see [`Watchpoints`].
    pub(crate) watchpoints: Arc<Watchpoints>,
    options: GDBOptions,
    /// VcpuTime stored after last tick.
    last_tick_time: Vec<VcpuTime>,
    /// Wall time across all vCPUs at the last *global* (processor-wide)
    /// round tick. Used to derive the wall-clock component of the
    /// [`GlobalDelta`] handed to the event distributor. Single value,
    /// since the global round spans all vCPUs.
    pub(crate) last_global_wall: Option<Instant>,
    current_vcpu: Option<usize>,
    _unused: PhantomData<GdbArchImpl>,
}

/// Functions needed outside of the gdbstub `Target` traits
impl<'a, GdbArchImpl> TargetImpl<'a, GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    /// Construct a new [TargetImpl] from the [ProcessorCore]
    /// Assumes that processor and cpu adhere to
    /// [Using _GdbExecutor_](super::plugin::GdbExecutor).
    pub(crate) fn new(
        vcpus: &'a mut PerVcpuSlice<VcpuCore>,
        core: &'a mut ProcessorCore,
        plugins: &'a mut Plugins,
        options: GDBOptions,
    ) -> Self {
        trace!("Creating TargetImpl");
        let reg_size = vcpus[0].cpu.architecture().core_register_size();
        let num_vcpus = vcpus.len();
        Self {
            vcpus,
            core,
            plugins,
            resume_actions: Default::default(),
            reg_size,
            breakpoint_state: Arc::new(BreakpointManager::default()),
            watchpoints: Arc::new(Watchpoints::new()),
            options,
            last_tick_time: vec![VcpuTime::default(); num_vcpus],
            last_global_wall: None,
            current_vcpu: None,
            _unused: PhantomData::<GdbArchImpl> {},
        }
    }

    /// Run `stride` instructions on a vCPU, recording the stride against its
    /// [`VcpuTime`](styx_core::core::VcpuCore::time) clock so that time accounting
    /// stays consistent across the step and continue paths.
    ///
    /// Returns `Some` if the CPU exit should be reported to the gdb client (a
    /// fault, stop request, or target exit), otherwise `None`.
    fn execute_stride(&mut self, vcpu_idx: usize, stride: u64) -> Option<event_loop::Event> {
        let tid = index_to_tid(vcpu_idx);
        let vcpu = &mut self.vcpus[vcpu_idx];
        let cpu_exit_condition = vcpu.execute_and_time(stride);
        if let Ok((report, duration)) = &cpu_exit_condition {
            vcpu.time.record_stride(report, stride, *duration);
        }
        self.handle_cpu_exit_code(cpu_exit_condition.map(|(r, _)| r.exit_reason), tid)
    }

    /// Single-step one instruction on a specific vCPU and check for events.
    fn step(&mut self, vcpu_idx: usize) -> Option<event_loop::Event> {
        let tid = index_to_tid(vcpu_idx);
        // Step 1 instruction, recording time so `VcpuTime` stays the single
        // source of truth for both execution paths.
        //  Bail if there is an event generated while running (target error)
        if let Some(event) = self.execute_stride(vcpu_idx, 1) {
            return Some(event);
        }

        // Cpu is stopped
        let pc = self.vcpus[vcpu_idx].cpu.pc().unwrap() as u32;

        // Watchpoints
        if let Some(hit) = self.watchpoints.pop_hit() {
            let hit_tid = hit.tid;
            let vcpu_tid = index_to_tid(vcpu_idx);
            if hit_tid != vcpu_tid {
                warn!("unexpected watchpoint hit tid {hit_tid} vs vcpu tid {vcpu_tid} not equal");
                // This may happen if a single step triggers multiple watchpoints
                // leaving a stale hit in the watchpoint pending stack.
                // Possible solution: clear the pending stack before step.
                //   Problem: would drop hit watchpoints.
                // Possible solution: don't worry about it and report correct tid
                //   since every hit watchpoint should be handled.
                //
                // I am not sure what is the correct behavior from gdb's perspective
                // (or if it is defined).
            }

            return Some(event_loop::Event::WatchWrite {
                addr: hit.address,
                tid,
            });
        }

        // Breakpoints
        if self.breakpoint_state.contains_active(&(pc as u64)) {
            return Some(event_loop::Event::Break(tid));
        }

        None
    }

    /// Advance the processor-wide clock and tick the event distributor
    /// once per round, mirroring the default executor.
    ///
    /// A round completes when every vCPU has advanced a full `cpu_epoch`
    /// of *simulated* time past the processor clock.
    /// Peripherals are only ticked when `tick_peripherals` is set.
    ///
    /// Plugin tickers run every round (independent of `tick_peripherals`), as
    /// they are not gated by [`StepIRQs`].
    fn global_round_tick(
        &mut self,
        cpu_epoch: u64,
        tick_peripherals: bool,
    ) -> Result<(), UnknownError> {
        // Find least simulated time of vCPUs.
        let Some(min_sim) = self.vcpus.iter().map(|v| v.time.simulated_time()).min() else {
            return Ok(());
        };

        let current_wall = Instant::now();
        while min_sim.saturating_sub(self.core.time.simulated_time()) >= cpu_epoch {
            let round_wall = current_wall.saturating_duration_since(
                self.last_global_wall.expect("no last global wall time"),
            );
            self.core.time.advance(cpu_epoch);
            self.last_global_wall = Some(current_wall);
            let delta = GlobalDelta::new(cpu_epoch, round_wall);
            if tick_peripherals {
                self.core.event_controller.tick(&delta, &mut *self.vcpus)?;
            }
            self.plugins.tick(self.core, &delta, &mut *self.vcpus)?;
        }
        Ok(())
    }

    /// Resume execution with round-robin multi-vCPU scheduling.
    pub(crate) fn resume(
        &mut self,
        mut poll_incoming_data: impl FnMut() -> bool,
    ) -> Result<RunEvent, UnknownError> {
        let num_vcpus = self.vcpus.len();
        let should_step_irqs = self.options.step_irqs == StepIRQs::Enabled;
        let cpu_epoch = self.options.cpu_epoch;

        // If any thread has a step action, the entire round runs in single-step
        // so non-stepped threads advance one instruction alongside. Resume
        // actions do not change during a `resume()` call, so this is computed
        // once.
        let any_stepping = self
            .resume_actions
            .values()
            .any(|a| matches!(a, ExecMode::Step | ExecMode::RangeStep(_, _)));

        loop {
            // Single-step the whole round when any thread is stepping, or when
            // watchpoints are armed (so we can pinpoint the exact instruction that
            // touched memory), otherwise run a full epoch at once.
            let any_watchpoints = self.watchpoints.any_watchpoints();
            let should_step = any_stepping || any_watchpoints;
            debug!("should step {should_step} = any threads have step action ({any_stepping}) || any_watchpoints ({any_watchpoints})");
            debug!(
                "thread actions: {}",
                self.resume_actions
                    .values()
                    .enumerate()
                    .fold(String::new(), |mut s, (i, m)| {
                        s.push_str(&format!("{i}:{m:?}"));
                        s
                    })
            );
            let start_vcpu = if !should_step {
                let start_vcpu = self.current_vcpu.map(|c| c + 1).unwrap_or(0);
                if start_vcpu >= num_vcpus {
                    0
                } else {
                    start_vcpu
                }
            } else {
                0
            };
            debug!("resuming from vcpu {start_vcpu}");
            for vcpu_idx in start_vcpu..num_vcpus {
                if !should_step {
                    self.current_vcpu = Some(vcpu_idx);
                }
                let tid = index_to_tid(vcpu_idx);
                // TODO(scheduler-locking): default to threads with no explicit action default to
                // `Continue`. We need to implement scheduler locking so that when
                // `set scheduler-locking on` will keep these threads stopped instead of advancing them.
                let action = self
                    .resume_actions
                    .get(&tid)
                    .copied()
                    .unwrap_or(ExecMode::Continue);

                let vcpu = &mut self.vcpus[vcpu_idx];
                let last_tick_time = &mut self.last_tick_time[vcpu_idx];

                // Once this vCPU has run an epoch's worth of instructions past the
                // last tick, tick peripherals/interrupts and poll the gdb client. The
                // instruction and wall-clock deltas are both read from `VcpuTime`. This
                // is checked *before* executing so the tick lands one stride after the
                // boundary is crossed (e.g. on the `cpu_epoch + 1`th single step).
                let cur = vcpu.time;
                let time_since_tick = cur - *last_tick_time;
                if time_since_tick.count >= cpu_epoch {
                    // `step_irqs` disabled suppresses peripheral/secondary-EC ticking
                    // while stepping; a plain `continue` always ticks.
                    // During a stepping round a non-stepped `Continue` vCPU still
                    // ticks here once it crosses its own epoch boundary.
                    if action == ExecMode::Continue || should_step_irqs {
                        if let Err(e) = styx_core::executor::post_stride_processing(
                            &mut self.vcpus[vcpu_idx],
                            &time_since_tick,
                        ) {
                            error!("post_stride_processing error: {e}");
                        }
                    }
                    // Re-baseline from `VcpuTime`. `wall_time` only accrues during
                    // `execute`, so it already excludes the ticking logic above.
                    *last_tick_time = cur;

                    // poll for incoming data
                    if poll_incoming_data() {
                        return Ok(RunEvent::IncomingData);
                    }
                }

                // Processor-wide round tick.
                // Checked every iteration so we don't miss ticks from an early return.
                // `step_irqs` disabled suppresses peripheral ticking
                // while stepping, just like the per-vCPU tick above.
                self.global_round_tick(
                    cpu_epoch,
                    action == ExecMode::Continue || should_step_irqs,
                )?;

                if should_step {
                    // check for:
                    // - target errors
                    // - breakpoints
                    // - watchpoints
                    debug!("stepping vcpu {vcpu_idx}");
                    if let Some(event) = self.step(vcpu_idx) {
                        trace!("event: {event:?}");
                        return Ok(RunEvent::Event(event));
                    }
                } else {
                    debug!("executing stride on vcpu {vcpu_idx}");
                    if let Some(event) = self.execute_stride(vcpu_idx, cpu_epoch) {
                        trace!("event: {event:?}");
                        // run the CPU epoch
                        return Ok(RunEvent::Event(event));
                    }
                }
            }

            debug!("stepping/exec done for vcpus");
            // End of round. A stepping thread reports `DoneStep` only after every vCPU
            // has advanced one instruction this round, so all vCPUs progress
            // symmetrically. `RangeStep` keeps issuing single-step rounds until its PC
            // leaves the range.
            if any_stepping {
                for vcpu_idx in 0..num_vcpus {
                    let tid = index_to_tid(vcpu_idx);
                    match self.resume_actions.get(&tid).copied() {
                        // if we are stepping then done after one step
                        Some(ExecMode::Step) => {
                            return Ok(RunEvent::Event(event_loop::Event::DoneStep(tid)));
                        }
                        // Step until the range, instead of attempting to do a bunch of fun
                        // math because variable length instruction architectures, we just
                        // single-step until the range is met. Single-stepping until the
                        // range is met.
                        Some(ExecMode::RangeStep(start, end)) => {
                            // check and see if we are no longer in the range of addresses to step through
                            let pc = self.vcpus[vcpu_idx].cpu.pc().unwrap();
                            if !(start..end).contains(&pc) {
                                return Ok(RunEvent::Event(event_loop::Event::DoneStep(tid)));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Logs the output of the cpu exit code, and determines if the
    /// targeted has exited, errored etc.
    ///
    /// The return of this method should be wrapped in a
    /// `RunEvent::Event()` to be send back to gdb
    fn handle_cpu_exit_code(
        &self,
        code: Result<TargetExitReason, UnknownError>,
        tid: Tid,
    ) -> Option<event_loop::Event> {
        match code {
            // The "OK" exit reasons here are:
            // - manually stopped the emulator
            // - instruction count met
            // - timeout met
            // - breakpoint hit
            // - target errored somehow
            Ok(reason) => {
                // check for breakpoint
                if self.breakpoint_state.paused() && reason == TargetExitReason::HostStopRequest {
                    // if we are currently paused, then a breakpoint
                    // called `self.pause()`, so propagate that breakpoint
                    info!("BP manager paused, propagating SwBreak event");
                    return Some(event_loop::Event::Break(tid));
                }
                // was emulation stopped
                if reason == TargetExitReason::HostStopRequest {
                    debug!("styx stopped cpu, gdb-target stopped");
                    return Some(event_loop::Event::StyxStoppedCpu(tid));
                }
                // check for exit conditions, and exit if the target
                // has crashed / exited for some reason
                if reason.fatal() || reason.is_stop_request() {
                    info!("Target stopped: `{}`", reason);
                    return Some(event_loop::Event::Exited(Ok(reason)));
                }
            }
            // target has exited with an error status
            Err(err) => {
                error!("Target exited due to error: {}", err);
                // translate the error reason into a pure `TargetExitReason`
                let translated = TargetExitReason::GeneralFault(err.to_string());
                // now return the error
                return Some(event_loop::Event::Exited(Err(translated)));
            }
        };
        None
    }
}

// --- gdbstub Target trait ---

impl<'a, GdbArchImpl> target::Target for TargetImpl<'a, GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    type Arch = GdbArchImpl; // implements `gdbstub::arch::Arch`
    type Error = &'static str;

    /// This is foundational support: read/write registers and memory addresses
    #[inline(always)]
    fn base_ops(&mut self) -> target::ext::base::BaseOps<'_, Self::Arch, Self::Error> {
        target::ext::base::BaseOps::MultiThread(self)
    }

    /// Breakpoint support. This is an example of IDET. This one happens to be
    /// nested, so it's more complicated.
    ///
    /// First, `support_breakpoints` is a required function for the gdbstub `Target`
    /// trait, which  returns an optional trait `BreakpointOps`. Returning `None`
    /// would say _I do not support breakpoints_. Returning `Some(self)` says:
    /// _I do support breakpoints. Call me back to see which kind_. Since this
    /// is a nested IDET, `Some(self)` triggers an additional callback
    /// to determine which kind of breakpoints are supported:
    /// ```text
    /// impl target::ext::breakpoints::Breakpoints for TargetImpl {
    ///   fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<'_, Self>>;
    ///   fn support_hw_watchpoint(&mut self) -> Option<HwWatchpointOps<'_, Self>>;
    /// ```
    /// Each of these, in turn, either return `None` or `Some(self)`, along with
    /// providing the trait implementations, as needed, to indicate/implement
    /// support for hardware and/or software breakpoints.
    #[inline(always)]
    fn support_breakpoints(
        &mut self,
    ) -> Option<target::ext::breakpoints::BreakpointsOps<'_, Self>> {
        Some(self)
    }

    /// Utility feature that supports the gdb `monitor` command
    #[inline(always)]
    fn support_monitor_cmd(&mut self) -> Option<target::ext::monitor_cmd::MonitorCmdOps<'_, Self>> {
        Some(self)
    }

    /// This tells GDB what the architecture is and gives basic definitions
    /// for registers.
    #[inline(always)]
    fn support_target_description_xml_override(
        &mut self,
    ) -> Option<
        target::ext::target_description_xml_override::TargetDescriptionXmlOverrideOps<'_, Self>,
    > {
        Some(self)
    }

    /// Not implemented
    #[inline(always)]
    fn support_extended_mode(
        &mut self,
    ) -> Option<target::ext::extended_mode::ExtendedModeOps<'_, Self>> {
        // Not implemented
        None
    }

    /// Not implemented
    #[inline(always)]
    fn support_section_offsets(
        &mut self,
    ) -> Option<target::ext::section_offsets::SectionOffsetsOps<'_, Self>> {
        // Not implemented
        None
    }

    /// Not implemented
    #[inline(always)]
    fn support_lldb_register_info_override(
        &mut self,
    ) -> Option<target::ext::lldb_register_info_override::LldbRegisterInfoOverrideOps<'_, Self>>
    {
        // Not implemented
        None
    }

    /// Not implemented
    #[inline(always)]
    fn support_memory_map(&mut self) -> Option<target::ext::memory_map::MemoryMapOps<'_, Self>> {
        // Not implemented
        None
    }

    /// Not implemented
    #[inline(always)]
    fn support_catch_syscalls(
        &mut self,
    ) -> Option<target::ext::catch_syscalls::CatchSyscallsOps<'_, Self>> {
        // Not implemented
        None
    }

    /// Not implemented
    #[inline(always)]
    fn support_host_io(&mut self) -> Option<target::ext::host_io::HostIoOps<'_, Self>> {
        // Not implemented
        None
    }

    /// Not implemented
    #[inline(always)]
    fn support_exec_file(&mut self) -> Option<target::ext::exec_file::ExecFileOps<'_, Self>> {
        // Not implemented
        None
    }

    /// Not implemented
    #[inline(always)]
    fn support_auxv(&mut self) -> Option<target::ext::auxv::AuxvOps<'_, Self>> {
        // Not implemented
        None
    }
}

// --- MultiThreadBase ---

impl<'a, GdbArchImpl> target::ext::base::multithread::MultiThreadBase
    for TargetImpl<'a, GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    /// Read the target's registers
    ///
    /// We just copy the registers results into the regs struct
    /// gdbstub calls this function, and then calls gdb_serialize with
    /// each value in the reg data struct
    fn read_registers(
        &mut self,
        regs: &mut GdbArchImpl::Registers,
        tid: Tid,
    ) -> TargetResult<(), Self> {
        let idx = tid_to_index(tid);
        // get a copy of all the registers in the machine
        // TODO: remove the unnecessary clone
        let backend_regs: Vec<(CpuRegister, GdbArchImpl::Usize)> = self.vcpus[idx]
            .cpu
            .register_values()
            .iter()
            .map(|(k, v)| (k.clone(), FromPrimitive::from_u32(*v).unwrap()))
            .collect();
        // update the backing reg store
        regs.set_register_tank(&backend_regs);
        Ok(())
    }

    /// Write the target's registers.
    ///
    /// ie, for each register in the reg_tank, set the emulator's
    /// corresponding register value
    fn write_registers(
        &mut self,
        regs: &GdbArchImpl::Registers,
        tid: Tid,
    ) -> TargetResult<(), Self> {
        let idx = tid_to_index(tid);
        // `regs` has a list of register values to set, so do so
        for (reg, value) in regs.register_tank().iter() {
            match self.reg_size {
                32 => self.vcpus[idx]
                    .cpu
                    .write_register(*reg, ToPrimitive::to_u32(value).unwrap())
                    .unwrap(),
                64 => self.vcpus[idx]
                    .cpu
                    .write_register(*reg, ToPrimitive::to_u64(value).unwrap())
                    .unwrap(),
                _ => (),
            }
        }
        Ok(())
    }

    /// Read the target's memory
    fn read_addrs(
        &mut self,
        start_addr: GdbArchImpl::Usize,
        data: &mut [u8],
        tid: Tid,
    ) -> TargetResult<usize, Self> {
        let addr: u64 = ToPrimitive::to_u64(&start_addr).unwrap();
        let idx = tid_to_index(tid);
        let vcpu = &mut self.vcpus[idx];
        match vcpu.mmu.virt_read_data(addr, data, vcpu.cpu.as_mut()) {
            Err(e) => {
                debug!("read_addrs(addr: 0x{:x}): {}", addr, e);
                Err(TargetError::NonFatal)
            }
            _ => Ok(data.len()),
        }
    }

    /// Write to the target's memory
    fn write_addrs(
        &mut self,
        start_addr: GdbArchImpl::Usize,
        data: &[u8],
        tid: Tid,
    ) -> TargetResult<(), Self> {
        let addr: u64 = ToPrimitive::to_u64(&start_addr).unwrap();
        let idx = tid_to_index(tid);
        let vcpu = &mut self.vcpus[idx];
        match vcpu.mmu.virt_write_data(addr, data, vcpu.cpu.as_mut()) {
            Err(e) => {
                debug!("write_addrs(addr: 0x{:x}): {}", addr, e);
                Err(TargetError::NonFatal)
            }
            _ => Ok(()),
        }
    }

    fn list_active_threads(
        &mut self,
        register_thread: &mut dyn FnMut(Tid),
    ) -> Result<(), Self::Error> {
        for i in 0..self.vcpus.len() {
            register_thread(index_to_tid(i));
        }
        Ok(())
    }

    #[inline(always)]
    fn support_single_register_access(
        &mut self,
    ) -> Option<target::ext::base::single_register_access::SingleRegisterAccessOps<'_, Tid, Self>>
    {
        Some(self)
    }

    /// This enables breakpoints, watchpoints, ...
    #[inline(always)]
    fn support_resume(
        &mut self,
    ) -> Option<target::ext::base::multithread::MultiThreadResumeOps<'_, Self>> {
        Some(self)
    }
}

// --- MultiThreadResume ---

impl<'a, GdbArchImpl> target::ext::base::multithread::MultiThreadResume
    for TargetImpl<'a, GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    fn resume(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn clear_resume_actions(&mut self) -> Result<(), Self::Error> {
        trace!("resume actions cleared");
        self.resume_actions.clear();
        Ok(())
    }

    fn set_resume_action_continue(
        &mut self,
        tid: Tid,
        signal: Option<Signal>,
    ) -> Result<(), Self::Error> {
        if signal.is_some() {
            warn!("GDB: resume: not handling signals");
        }
        self.resume_actions.insert(tid, ExecMode::Continue);
        Ok(())
    }

    #[inline(always)]
    fn support_single_step(
        &mut self,
    ) -> Option<target::ext::base::multithread::MultiThreadSingleStepOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_range_step(
        &mut self,
    ) -> Option<target::ext::base::multithread::MultiThreadRangeSteppingOps<'_, Self>> {
        Some(self)
    }

    fn support_scheduler_locking(
        &mut self,
    ) -> Option<target::ext::base::multithread::MultiThreadSchedulerLockingOps<'_, Self>> {
        Some(self)
    }
}

// --- MultiThreadSingleStep ---

impl<'a, GdbArchImpl> target::ext::base::multithread::MultiThreadSingleStep
    for TargetImpl<'a, GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    fn set_resume_action_step(
        &mut self,
        tid: Tid,
        signal: Option<Signal>,
    ) -> Result<(), Self::Error> {
        if signal.is_some() {
            warn!("GDB: step: not handling signals");
        }
        debug!(
            "gdb set resume action for thread {tid} (vcpu {}) to step",
            tid_to_index(tid)
        );
        self.resume_actions.insert(tid, ExecMode::Step);
        Ok(())
    }
}

// --- MultiThreadRangeStepping ---

impl<'a, GdbArchImpl> target::ext::base::multithread::MultiThreadRangeStepping
    for TargetImpl<'a, GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    fn set_resume_action_range_step(
        &mut self,
        tid: Tid,
        start: GdbArchImpl::Usize,
        end: GdbArchImpl::Usize,
    ) -> Result<(), Self::Error> {
        let start = ToPrimitive::to_u64(&start).unwrap();
        let end = ToPrimitive::to_u64(&end).unwrap();
        self.resume_actions
            .insert(tid, ExecMode::RangeStep(start, end));
        Ok(())
    }
}

// --- SingleRegisterAccess<Tid> ---

impl<'a, GdbArchImpl> target::ext::base::single_register_access::SingleRegisterAccess<Tid>
    for TargetImpl<'a, GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    fn read_register(
        &mut self,
        tid: Tid,
        reg_id: GdbArchImpl::RegId,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let idx = tid_to_index(tid);
        trace!("read_register {:?} (vcpu {})", reg_id, idx);
        match self.reg_size {
            32 => {
                buf.copy_from_slice(
                    &self.vcpus[idx]
                        .cpu
                        .read_register::<u32>(reg_id)
                        .unwrap()
                        .to_le_bytes(),
                );
                Ok(buf.len())
            }
            64 => {
                buf.copy_from_slice(
                    &self.vcpus[idx]
                        .cpu
                        .read_register::<u64>(reg_id)
                        .unwrap()
                        .to_le_bytes(),
                );
                Ok(buf.len())
            }
            _ => Err(().into()),
        }
    }

    fn write_register(
        &mut self,
        tid: Tid,
        reg_id: GdbArchImpl::RegId,
        val: &[u8],
    ) -> TargetResult<(), Self> {
        let idx = tid_to_index(tid);
        trace!("write_register: {:?} (vcpu {})", reg_id, idx);

        // Write is received in target endianness so we have to account for
        // endian to get value
        let v = match self.vcpus[idx].cpu.endian() {
            ArchEndian::LittleEndian => u32::from_le_bytes(
                val.try_into()
                    .map_err(|_| TargetError::Fatal("invalid data"))?,
            ),
            ArchEndian::BigEndian => u32::from_be_bytes(
                val.try_into()
                    .map_err(|_| TargetError::Fatal("invalid data"))?,
            ),
        };

        let write_result = match self.reg_size {
            32 => self.vcpus[idx].cpu.write_register(reg_id, v),
            64 => self.vcpus[idx].cpu.write_register(reg_id, v as u64),
            _ => Ok(()),
        };

        match write_result {
            Ok(_) => Ok(()),
            Err(error) => {
                warn!("write_register({:?}, {:?}): {}", reg_id, val, error);
                Err(TargetError::NonFatal)
            }
        }
    }
}

/// Asserts we have homogenus processor and return its archdef.
fn assert_single_arch_processor(
    vcpus: &PerVcpuSlice<VcpuCore>,
) -> Result<&dyn ArchitectureDef, TargetError<&'static str>> {
    match vcpus
        .iter()
        .map(|vcpu| vcpu.cpu.architecture().architecture())
        .all_equal_value()
    {
        Ok(_) => Ok(()),
        Err(Some((one, two))) => {
            warn!(
                "processor with multiple different architectures not supported by gdb; \
                     processor has arches {one} and {two}."
            );
            Err(TargetError::Fatal(
                "processor with multiple architectures not supported by styx-gdbserver",
            ))
        }
        Err(None) => {
            unreachable!("PerVcpuSlice is never empty")
        }
    }?;

    // now we know all cpus have same arch
    Ok(vcpus.first().cpu.architecture())
}

// --- TargetDescriptionXmlOverride ---

impl<'a, GdbArchImpl> target::ext::target_description_xml_override::TargetDescriptionXmlOverride
    for TargetImpl<'a, GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    /// This generates/sends GDB XML content which describes basic architecture
    /// and layout of the registers.
    fn target_description_xml(
        &self,
        annex: &[u8],
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        // All vcpus should have the same architecture, just grab vcpu0's
        let xml_string = assert_single_arch_processor(self.vcpus)?
            .target_xml(annex)
            .ok_or(TargetError::NonFatal)?;
        trace!("{}", xml_string);
        let b = xml_string.as_str().trim().as_bytes();
        let data_len = b.len(); // bytes we need to copy

        //
        // now copy the xml into buf
        //

        // not going to copy any bytes if we're already at the end
        // of the input buffer, after this `offset` is known to be
        // < `data_len`
        if offset >= data_len as u64 {
            return Ok(0);
        }

        // get the actual number of bytes we can copy
        let output_len = length;
        let input_len = data_len - offset as usize; // length of data to copy
        let len_copy = input_len.min(output_len).min(buf.len());

        // perform the memcpy
        let input_start = offset as usize;
        let input_end = input_start + len_copy;
        let dest_end = len_copy;

        buf[..dest_end].copy_from_slice(&b[input_start..input_end]);

        // return the number of bytes we actually copied
        Ok(len_copy)
    }
}

// --- Breakpoints ---

impl<'a, GdbArchImpl> target::ext::breakpoints::Breakpoints for TargetImpl<'a, GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    #[inline(always)]
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_hw_watchpoint(&mut self) -> Option<HwWatchpointOps<'_, Self>> {
        Some(self)
    }
}

/// This implementation handles breakpoints
/// See note about breakpoints ng reset on [TargetImpl]
impl<'a, GdbArchImpl> target::ext::breakpoints::SwBreakpoint for TargetImpl<'a, GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    /// Add the breakpoint to `self.breakpoints`
    /// Return `Ok(false)` if the operation could not be completed
    fn add_sw_breakpoint(
        &mut self,
        addr: GdbArchImpl::Usize,
        kind: GdbArchImpl::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        let addr = ToPrimitive::to_u64(&addr).unwrap();
        info!("Client requested to add bp kind=`{kind:?}` @ `{addr:08x?}`");

        // enforce only 1 breakpoint at a location
        if self.breakpoint_state.contains_active(&addr) {
            debug!("gdbserver already contains active bp @ `{addr:08x?}`");
            return Ok(true);
        }
        // if we already have this breakpoint inserted into the
        // runtime, then re-activate it (even if we are at this current
        // address that is OK since we check for that in the breakpoint handler)
        if self.breakpoint_state.contains_not_active(&addr).found() {
            self.breakpoint_state.activate(&addr);
            debug!("gdbserver activated old bp @ `{addr:08x?}`");
            return Ok(true);
        }

        debug!("gdbserver is adding new breakpoint @ `{addr:08x?}`");
        // add code hook, propagate errors if necessary
        let mut tokens = Vec::with_capacity(self.vcpus.len());
        for vcpu in self.vcpus.iter_mut() {
            let bp_state = self.breakpoint_state.clone();
            match vcpu
                .cpu
                .virt_code_hook(addr, addr, Box::new(GdbBreakpointHook(bp_state)))
            {
                Ok(token) => tokens.push(token),
                Err(err) => {
                    warn!("Failed to add bp at {:#x}: {err:?}", addr);
                    // TODO: cleanup other vpus that could have add code hooks added.
                    return Ok(false);
                }
            }
        }
        self.breakpoint_state.add_breakpoint(tokens, addr);
        Ok(true)
    }

    /// Remove the breakpoint from `self.breakpoints`
    /// Return `Ok(false)` if the operation could not be completed
    fn remove_sw_breakpoint(
        &mut self,
        addr: GdbArchImpl::Usize,
        _kind: GdbArchImpl::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        if let Some(addr) = ToPrimitive::to_u64(&addr) {
            trace!("gdbserver received deactivate breakpoint: {:#x}", addr);
            if self.breakpoint_state.deactivate(&addr).found() {
                return Ok(true);
                // We don't remove same-pc breakpoints because this might break the cpu backend.
                // TODO: maybe remove non-same-pc breakpoints.
            }
            warn!("Could not find address: `{:#x}` in valid breakpoints", addr);
        } else {
            warn!("Could not convert address to u64: `{:?}`", addr);
        }
        Ok(false)
    }
}

/// This implementation handles memory based watchpoints
/// Read, ReadWrite are not supported yet
/// See note about watchpoints getting reset on [TargetImpl]
impl<'a, GdbArchImpl> target::ext::breakpoints::HwWatchpoint for TargetImpl<'a, GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    /// Gdb request to add watchpoint.
    ///
    /// Return `Ok(false)` if the operation could not be completed.
    fn add_hw_watchpoint(
        &mut self,
        addr: GdbArchImpl::Usize,
        _len: GdbArchImpl::Usize,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        let addr = ToPrimitive::to_u64(&addr).unwrap();
        match kind {
            WatchKind::Write => Ok(self.watchpoints.add_write_watchpoint(self.vcpus, addr)),
            // not implemented *yet*
            WatchKind::Read | WatchKind::ReadWrite => Ok(false),
        }
    }

    /// Gdb request to remove the watchpoints in `[addr, addr + len)`.
    ///
    /// Return `Ok(false)` if no watchpoint was found in the range.
    fn remove_hw_watchpoint(
        &mut self,
        addr: GdbArchImpl::Usize,
        len: GdbArchImpl::Usize,
        // unclear whether we need to check on this?
        _kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        let addr = ToPrimitive::to_u64(&addr).unwrap();
        let len = ToPrimitive::to_u64(&len).unwrap();
        trace!("remove_hw_watchpoint(addr: {addr:#x}, size: {len})");

        // check the entire address range
        for addr in addr..(addr + len) {
            if self.watchpoints.remove_watchpoint(self.vcpus, addr) {
                trace!("remove_hw_watchpoint: removed watchpoint");
                return Ok(true);
            }
        }
        trace!("remove_hw_watchpoint: failed to remove anything");
        // we did not remove anything
        Ok(false)
    }
}

impl<'a, GdbArchImpl> target::ext::thread_extra_info::ThreadExtraInfo
    for TargetImpl<'a, GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    fn thread_extra_info(&self, tid: Tid, buf: &mut [u8]) -> Result<usize, Self::Error> {
        // Provide extra information about a thread
        // A string can be copied into buf that will then be displayed to the client. The string is displayed as (value), such as:
        // Thread 1.1 (value)

        // For styx we just write the vcpuid.

        let vcpuid = tid_to_index(tid);
        let vcpuindex_str = format!("vpu: {vcpuid}");
        let bytes = vcpuindex_str.as_bytes();
        let len = bytes.len().min(buf.len());
        buf[0..len].copy_from_slice(&bytes[0..len]);

        Ok(len)
    }
}

impl<'a, GdbArchImpl> target::ext::base::multithread::MultiThreadSchedulerLocking
    for TargetImpl<'a, GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    fn set_resume_action_scheduler_lock(&mut self) -> Result<(), Self::Error> {
        // TODO(scheduler-locking) according to then scheduler locking
        // contract, this should stop our executor from executing other
        // threads while this is on.
        //
        // Currently, all threads are stepped/continued, no matter
        // the scheduler locking setting.
        //
        // We had to implement this trait to avoid a gdbstub fatal error after
        // updating to 0.7.10.
        warn!("`scheduler-lock on` was set but gdbserver does not implement this yet. Default behavior is for all threads to continue.");
        Ok(())
    }
}
