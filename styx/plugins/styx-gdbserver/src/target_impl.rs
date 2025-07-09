// SPDX-License-Identifier: BSD-2-Clause
//! Defines [`TargetImpl`] and implements [`_gdbstub Target traits_`](https://docs.rs/gdbstub/0.6.6/gdbstub/target/trait.Target.html)
//! traits.
//!
//! [`TargetImpl`] sits between [`gdbstub`] and the [`CpuBackend`]
//! to control cpu execution and the various `gdbstub` trait implementations
//! found in this module.
//! The [`TargetImpl`] traits are essentially a collection of handlers invoked by the _gdb
//! client_ over the gdb serial protocol. The gdbstub uses a technique called
//! _Inlineable Dynamic Extension Traits_ (_IDETs_) to expose the interface
//! to the GDB protocol.
//! See
//! [_Implementing Target_](https://docs.rs/gdbstub/0.6.6/gdbstub/target/index.html#implementing-target)
//! for an explanation, see `support_breakpoints` in the source for an example.
//! There is also discussion
//! [`here`](https://github.com/daniel5151/inlinable-dyn-extension-traits/blob/master/writeup.md)
use crate::{
    event_loop::{self, RunEvent},
    mem_watch::{Access, MemHookCache},
};
use gdbstub::{
    common::Signal,
    target::{
        self,
        ext::breakpoints::{HwWatchpointOps, SwBreakpointOps, WatchKind},
        TargetError, TargetResult,
    },
};
use num_traits::{FromPrimitive, ToPrimitive};
use std::marker::PhantomData;
use styx_core::{
    cpu::{
        arch::{CpuRegister, GdbRegistersHelper},
        ArchEndian, TargetExitReason,
    },
    executor::Delta,
    hooks::CodeHook,
};
use styx_core::{hooks::MemoryWriteHook, prelude::*};
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
/// When [`TargetImpl`] continues, the breakpoint will be immediately
/// hit again, *but* `bp_state.paused` == `true` this time around. This
/// time it clears the flag and lets the cpu continue execution as normal.
///
/// This process continues ad infinium.
struct GdbBreakpointHook(Arc<BreakpointManager>);
impl CodeHook for GdbBreakpointHook {
    fn call(&mut self, proc: CoreHandle) -> Result<(), UnknownError> {
        // let bp_state: Arc<BreakpointManager> = userdata.downcast().unwrap();

        let pc = proc.cpu.pc().unwrap();
        // check if pc is in our breakpoints, if not then bail
        if !self.0.contains_active(&pc) {
            trace!("HOOK: `0x{pc:08x}` is not in `self.active_breakpoints`");
            return Ok(());
        }

        debug!("HOOK: pc@{pc:08x} is an active breakpoint");
        // if we are paused at current location, unpause self, and then return
        // in some cases we *immediately* get restarted @ same address so we
        // need this
        if let Some(paused_address) = self.0.paused_address() {
            debug!("HOOK: gdb breakpoint hook, bp_state is PAUSED");
            if paused_address == pc {
                debug!("bp_state is paused on current pc, will not stop exceution");
                self.0.unpause();
                return Ok(());
            }
        }

        debug!("HOOK: gdb breakpoint hook, bp_state is UNPAUSED");
        // we are not yet paused, so we need to pause self and stop the cpu.
        // once the cpu is stopped, then the control flow in `self.resume` will
        // continue, and the breakpoint event will be propagated because
        // `self.paused` is now set
        self.0.pause(pc);
        proc.cpu.stop();
        debug!("HOOK: gdb breakpoint hook stopped cpu");
        Ok(())
    }
}

/// Track the current gdb execution mode - used let the event loop
/// know that we want to resume target (emulator) execution
#[derive(Debug)]
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
    pub(crate) proc: &'a mut ProcessorCore,
    /// Current execution mode
    pub(crate) exec_mode: ExecMode,
    /// Addresses of watch points from the gdb client. These get reset on each
    /// emulation start/stop. When the user triggers a _resume_ of the emulation
    /// (nexti, step, continue) `add_hw_breakpoint` is called. When the cpu finishes
    /// the directive (and is stopped) `remove_hw_breakpoint` is called.
    pub(crate) watchpoints: Vec<u64>,
    /// The emulator's core register size in bits (eg: 32 or 64)
    pub(crate) reg_size: usize,
    /// Used to check if we are paused in a breakpoint etc. or not
    breakpoint_state: Arc<BreakpointManager>,
    /// Tracks `styx_core::cpu::hooks::HookType::MEM_WRITE` hooks
    /// TODO: make sure this really does
    pub(crate) mem_hook_cache: Arc<MemHookCache>,
    _unused: PhantomData<GdbArchImpl>,
}

/// How many instructions to segment "epoch"'s with
const CPU_EPOCH_SIZE: u64 = 1024;

/// Functions needed outside of the gdbstub `Target` traits
impl<'a, GdbArchImpl> TargetImpl<'a, GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    /// Gets the current state of `self.paused`
    #[inline(always)]
    #[allow(dead_code)]
    fn paused(&self) -> bool {
        self.breakpoint_state.paused()
    }

    /// Construct a new [TargetImpl] from the [ProcessorCore]
    /// Assumes that processor and cpu adhere to
    /// [Using _GdbExecutor_](super::plugin::GdbExecutor).
    pub(crate) fn new(mach: &'a mut ProcessorCore) -> Self {
        trace!("Creating TargetImpl");
        let reg_size = mach.cpu.architecture().core_register_size();

        Self {
            proc: mach,
            exec_mode: ExecMode::Continue,
            watchpoints: Vec::new(),
            reg_size,
            breakpoint_state: Arc::new(BreakpointManager::default()),
            mem_hook_cache: Arc::new(MemHookCache::new()),
            _unused: PhantomData::<GdbArchImpl> {},
        }
    }

    pub fn target_cpu(&mut self) -> &mut dyn CpuBackend {
        self.proc.cpu.as_mut()
    }

    // pub fn get_target_xml(&mut self) {
    //     if let Some(xml_string) = self.target_cpu().architecture().target_xml(annex) {
    //         trace!("{}", xml_string);
    //         let b = xml_string.as_str().trim().as_bytes();
    //         let data_len = b.len(); // bytes we need to copy

    //         //
    //         // now copy the xml into buf
    //         //

    //         // not going to copy any bytes if we're already at the end
    //         // of the input buffer, after this `offset` is known to be
    //         // < `data_len`
    //         if offset >= data_len as u64 {
    //             return Ok(0);
    //         }

    //         // get the actual number of bytes we can copy
    //         let output_len = length;
    //         let input_len = data_len - offset as usize; // length of data to copy
    //         let len_copy = input_len.min(output_len);

    //         // perform the memcpy
    //         let input_start = offset as usize;
    //         let input_end = input_start + len_copy;
    //         let dest_end = len_copy;

    //         buf[..dest_end].copy_from_slice(&b[input_start..input_end]);

    //         // return the number of bytes we actually copied
    //         Ok(len_copy)
    //     } else {
    //         Err(TargetError::NonFatal)
    //     }
    // }

    /// Tell the processor to run a step one. After the step is complete,
    /// check to see if any `watch` or `break` points have been hit. If NOT,
    /// poke the `EventController` attached to the [`Processor`].
    ///
    /// ## Returns
    /// `Option<event_loop::Event>` - an appropriate
    /// [`Event`](event_loop::Event) - or [None] if no events occurred.
    fn step(&mut self) -> Option<event_loop::Event> {
        // Step 1 instruction
        //  Bail if there is an event generated while running (target error)
        let cpu_exit_condition =
            self.proc
                .cpu
                .execute(&mut self.proc.mmu, &mut self.proc.event_controller, 1);
        if let Some(event) =
            self.handle_cpu_exit_code(cpu_exit_condition.map(|report| report.exit_reason))
        {
            return Some(event);
        }

        // Cpu is stopped
        let pc = self.target_cpu().pc().unwrap() as u32;

        // Watchpoints
        if self.mem_hook_cache.pending_len() > 0 {
            for w in self.watchpoints.iter() {
                if let Some(hit_addr) = self.mem_hook_cache.take(*w) {
                    return Some(event_loop::Event::WatchWrite(hit_addr));
                }
            }
        }

        // Breakpoints
        if self.breakpoint_state.contains_active(&(pc as u64)) {
            return Some(event_loop::Event::Break);
        }

        // NOTE: unlike in `continue` we DO NOT
        // latch the next interrupt as the user is single-stepping through code

        None
    }

    /// This function is called by the
    /// [`EmuGdbEventLoop`](super::event_loop::EmuGdbEventLoop) each time
    /// we want to *resume processor execution*.
    ///
    /// Execution is resumed based on `self.exec_mode` [`ExecMode`]
    ///
    /// The `poll_incoming_data` parameter a function callback to peek at the comms
    /// channel to the gdb client. If we are in [`ExecMode::Continue`], check for
    /// input after `1024` steps by peeking at the incoming bytes (a way to
    /// check for Ctrl-C and break with [`RunEvent::IncomingData`] to process
    /// the event)
    pub(crate) fn resume(&mut self, mut poll_incoming_data: impl FnMut() -> bool) -> RunEvent {
        match self.exec_mode {
            // if we're stepping then we are done after one step
            ExecMode::Step => RunEvent::Event(self.step().unwrap_or(event_loop::Event::DoneStep)),
            // continue until something pauses execution
            // NOTE: if any watchpoints are set then we must single step
            // because we need to check the memory state every single
            // instruction
            ExecMode::Continue => {
                // If the user has any watchpoints, we need to handle
                // the extra logic accordingly
                if !self.watchpoints.is_empty() {
                    let mut cycles: u64 = 0;

                    loop {
                        // every 'epoch' we need to insert an interrupt, and check
                        // for new data from the `gdb` client
                        if cycles % CPU_EPOCH_SIZE == 0 {
                            // insert interrupt
                            _ = self
                                .proc
                                .event_controller
                                .next(self.proc.cpu.as_mut(), &mut self.proc.mmu);

                            // assume 1 ns per instruction
                            let delta = Delta {
                                time: std::time::Duration::from_nanos(CPU_EPOCH_SIZE),
                                count: CPU_EPOCH_SIZE,
                            };
                            self.proc
                                .event_controller
                                .tick(self.proc.cpu.as_mut(), &mut self.proc.mmu, &delta)
                                .unwrap();

                            // poll for incoming data
                            if poll_incoming_data() {
                                break RunEvent::IncomingData;
                            }
                        }
                        cycles += 1;

                        // check for:
                        // - target errors
                        // - breakpoints
                        // - watchpoints
                        // Because we need to watch for memory accesses, we must single-step
                        // because we need to know *exactly* which instruction caused the
                        // memory access
                        if let Some(event) = self.step() {
                            break RunEvent::Event(event);
                        };
                    }
                } else {
                    // loop until there's a reason to exit
                    loop {
                        // poll for incoming data before every epoch
                        if poll_incoming_data() {
                            debug!("runtime poller found incoming data from gdb clien");
                            break RunEvent::IncomingData;
                        }

                        // bump the event controller
                        _ = self
                            .proc
                            .event_controller
                            .next(self.proc.cpu.as_mut(), &mut self.proc.mmu);

                        // assume 1 ns per instruction
                        let delta = Delta {
                            time: std::time::Duration::from_nanos(CPU_EPOCH_SIZE),
                            count: CPU_EPOCH_SIZE,
                        };
                        self.proc
                            .event_controller
                            .tick(self.proc.cpu.as_mut(), &mut self.proc.mmu, &delta)
                            .unwrap();

                        // run the CPU epoch
                        let cpu_exit_condition = self.proc.cpu.execute(
                            &mut self.proc.mmu,
                            &mut self.proc.event_controller,
                            CPU_EPOCH_SIZE,
                        );
                        if let Some(event) = self.handle_cpu_exit_code(
                            cpu_exit_condition.map(|report| report.exit_reason),
                        ) {
                            break RunEvent::Event(event);
                        }
                    }
                }
            }

            // step until the range, instead of attempting to do
            // a bunch of fun math because variable length instruction (VLIW)
            // architectures, we just single-step until the range is met.
            // TODO: add a temp breakpoint or breakpoint at the end of the
            // range and then remove it when hit
            ExecMode::RangeStep(start, end) => {
                let mut cycles: u64 = 0;
                loop {
                    if cycles % CPU_EPOCH_SIZE == 0 {
                        // poll for incoming data
                        if poll_incoming_data() {
                            break RunEvent::IncomingData;
                        }
                    }
                    cycles += 1;

                    // check for:
                    // - target errors
                    // - breakpoints
                    // - watchpoints
                    // Because we need to watch for memory accesses, we must single-step
                    // because we need to know *exactly* which instruction caused the
                    // memory access
                    if let Some(event) = self.step() {
                        break RunEvent::Event(event);
                    };

                    // check and see if we are no longer in the range off addresses
                    // to step through
                    // XXX: this is a hack to work aroudn VLIW stuff, so it looks
                    // disgusting
                    let pc = self.target_cpu().pc().unwrap();
                    if !(start..end).contains(&pc) {
                        break RunEvent::Event(event_loop::Event::DoneStep);
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
    #[inline]
    fn handle_cpu_exit_code(
        &self,
        code: Result<TargetExitReason, UnknownError>,
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
                if self.paused() && reason == TargetExitReason::HostStopRequest {
                    // if we are currently paused, then a breakpoint
                    // called `self.pause()`, so propagate that breakpoint
                    info!("BP manager paused, beginning propagating SwBreak event");
                    return Some(event_loop::Event::Break);
                }

                // was emulation stopped
                if reason == TargetExitReason::HostStopRequest {
                    debug!("styx called Processor::cpu_stop() so gdb-target has stopped");
                    return Some(event_loop::Event::StyxStoppedCpu);
                }

                // check for exit conditions, and exit if the target
                // has crashed / exited for some reason
                if reason.fatal() || reason.is_stop_request() {
                    info!("Target has stopped due to: `{}`", reason);
                    return Some(event_loop::Event::Exited(Ok(reason)));
                }
            }
            // target has exited with an error status
            Err(err) => {
                error!("Target exited due to error: {}", err);

                // translate the error reason into a pure `TargetExitReason`
                let translated_reason = TargetExitReason::GeneralFault(err.to_string());

                // now return the error
                return Some(event_loop::Event::Exited(Err(translated_reason)));
            }
        };

        None
    }
}

/// This trait just sets up what features are supported using the `IDET` pattern.
///
/// The general pattern is to return an Impl if supported `Some(self)` or
/// `None` if the feature is not supported.
///
/// If the operation is supported, additional traits are implemented
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
        target::ext::base::BaseOps::SingleThread(self)
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

/// Registers must be de/serialized in the order specified by the architecture's
/// `<target>.xml` as known and understood by gdb
///
/// There is pre-packaged target description XML data accessible via `styx-util`
///
/// ## Implementation notes:
///
/// - `impl Registers for TargetImpl` would have negated the need
///   for the `reg_tank` buffer, but it was a more tangled option as
///   `Registers` also needs Default + Debug + Clone + PartialEq
///
/// - gdbstub always calls `Target::read_registers()` followed by a
///   call to `gdb_serialize` - making this StyxReg struct just an intermediate
///   buffer serving no purpose. The trait impl could go on TargetImpl, however
///   the trait is defined to also implement `Eq` and `PartialEq`, making it
///   a little less tempting
///
/// When writing registers from the gdb client
///     1) Target::Registers::gdb_deserialize
///     2) Target::write_registers()
/// When reading registers from the gdb client
///     1) Target::write_registers()
///     2) Target::Registers::gdb_deserialize
///
/// deserialize:
/// - Specifically, take the values from GDB, and put them in the reg_tank
///
/// This seems to only get called if
/// [`target::ext::base::single_register_access::SingleRegisterAccessOps`]
/// is not supported.
///
/// The call flow is:
///     - write register from gdb client (ex: set $r0 = 0xdead)
///     - this method called (Target::Registers::gdb_deserialize)
///     - Target::write_registers
///     - Target::read_registers
///     - Target::Registers::gdb_serialize
///
impl<'a, GdbArchImpl> target::ext::base::singlethread::SingleThreadBase
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
    fn read_registers(&mut self, regs: &mut GdbArchImpl::Registers) -> TargetResult<(), Self> {
        trace!("GdbExecutor::read_registers");

        // get a copy of all the registers in the machine
        // TODO: remove the unnecessary clone
        let backend_regs: Vec<(CpuRegister, GdbArchImpl::Usize)> = self
            .target_cpu()
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
    fn write_registers(&mut self, regs: &GdbArchImpl::Registers) -> TargetResult<(), Self> {
        trace!("GdbExecutor::write_registers");

        // `regs` has a list of register values to set, so do so
        for (reg, value) in regs.register_tank().iter() {
            match self.reg_size {
                32 => self
                    .target_cpu()
                    .write_register(*reg, ToPrimitive::to_u32(value).unwrap())
                    .unwrap(),
                64 => self
                    .target_cpu()
                    .write_register(*reg, ToPrimitive::to_u64(value).unwrap())
                    .unwrap(),
                _ => (),
            }
        }

        Ok(())
    }

    #[inline(always)]
    fn support_single_register_access(
        &mut self,
    ) -> Option<target::ext::base::single_register_access::SingleRegisterAccessOps<'_, (), Self>>
    {
        Some(self)
    }

    /// Read the target's memory
    #[inline(always)]
    fn read_addrs(
        &mut self,
        start_addr: GdbArchImpl::Usize,
        data: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let addr: u64 = num_traits::ToPrimitive::to_u64(&start_addr).unwrap();

        if let Err(e) = self.proc.mmu.read_data(addr, data) {
            debug!("GdbExecutor::read_addrs(addr: `0x{:x}`): {}", addr, e);
            Err(gdbstub::target::TargetError::NonFatal)
        } else {
            Ok(data.len())
        }
    }

    /// Write to the target's memory
    #[inline(always)]
    fn write_addrs(
        &mut self,
        start_addr: GdbArchImpl::Usize,
        data: &[u8],
    ) -> TargetResult<(), Self> {
        let addr: u64 = num_traits::ToPrimitive::to_u64(&start_addr).unwrap();

        if let Err(e) = self.proc.mmu.write_data(addr, data) {
            debug!("GdbExecutor::write_addrs(addr: `0x{:x}`): {}", addr, e);
            Err(gdbstub::target::TargetError::NonFatal)
        } else {
            Ok(())
        }
    }

    /// This enables breakpoints, watchpoints, ...
    #[inline(always)]
    fn support_resume(
        &mut self,
    ) -> Option<target::ext::base::singlethread::SingleThreadResumeOps<'_, Self>> {
        Some(self)
    }
}

impl<'a, GdbArchImpl> target::ext::base::singlethread::SingleThreadResume
    for TargetImpl<'a, GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    fn resume(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        if let Some(_signal) = signal {
            warn!("GDB: resume: not handling signals");
        }
        trace!("GDB: resume sets exec_mode to ExecMode::Continue");
        self.exec_mode = ExecMode::Continue;
        Ok(())
    }

    #[inline(always)]
    fn support_single_step(
        &mut self,
    ) -> Option<target::ext::base::singlethread::SingleThreadSingleStepOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_range_step(
        &mut self,
    ) -> Option<target::ext::base::singlethread::SingleThreadRangeSteppingOps<'_, Self>> {
        Some(self)
    }

    /// Reverse continue/step not supported
    #[inline(always)]
    fn support_reverse_cont(
        &mut self,
    ) -> Option<target::ext::base::reverse_exec::ReverseContOps<'_, (), Self>> {
        None
    }

    /// Reverse continue/step not supported
    #[inline(always)]
    fn support_reverse_step(
        &mut self,
    ) -> Option<target::ext::base::reverse_exec::ReverseStepOps<'_, (), Self>> {
        None
    }
}

impl<'a, GdbArchImpl> target::ext::base::singlethread::SingleThreadSingleStep
    for TargetImpl<'a, GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    /// By setting [ExecMode], this gets injected into the event loop
    fn step(&mut self, _: Option<Signal>) -> Result<(), Self::Error> {
        trace!("Setting self.exec_mode to ExecMode::Step");
        self.exec_mode = ExecMode::Step;
        Ok(())
    }
}

impl<'a, GdbArchImpl> target::ext::base::singlethread::SingleThreadRangeStepping
    for TargetImpl<'a, GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    fn resume_range_step(
        &mut self,
        start: GdbArchImpl::Usize,
        end: GdbArchImpl::Usize,
    ) -> Result<(), Self::Error> {
        trace!("GDB: resume:self.exec_mode = ExecMode::RangeStep ");
        let start = num_traits::ToPrimitive::to_u64(&start).unwrap();
        let end = num_traits::ToPrimitive::to_u64(&end).unwrap();

        self.exec_mode = ExecMode::RangeStep(start, end);
        Ok(())
    }
}

impl<'a, GdbArchImpl> target::ext::base::single_register_access::SingleRegisterAccess<()>
    for TargetImpl<'a, GdbArchImpl>
where
    GdbArchImpl: gdbstub::arch::Arch,
    GdbArchImpl::Registers: styx_core::cpu::arch::GdbRegistersHelper,
    GdbArchImpl::RegId: super::GdbArchIdSupportTrait,
{
    fn read_register(
        &mut self,
        _tid: (),
        reg_id: GdbArchImpl::RegId,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        trace!("read_register {:?}", reg_id);
        match self.reg_size {
            32 => {
                buf.copy_from_slice(
                    &self
                        .target_cpu()
                        .read_register::<u32>(reg_id)
                        .unwrap()
                        .to_le_bytes(),
                );
                Ok(buf.len())
            }
            64 => {
                buf.copy_from_slice(
                    &self
                        .target_cpu()
                        .read_register::<u64>(reg_id)
                        .unwrap()
                        .to_le_bytes(),
                );
                Ok(buf.len())
            }
            _ => Err(().into()),
        }
    }

    // does not support anything except 32 bit registers
    fn write_register(
        &mut self,
        _tid: (),
        reg_id: GdbArchImpl::RegId,
        val: &[u8],
    ) -> TargetResult<(), Self> {
        trace!("GDB: write_register: {:?}", reg_id);

        // Write is received in target endianness so we have to account for
        // endian to get value
        let v = match self.target_cpu().endian() {
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
            32 => self.target_cpu().write_register(reg_id, v),
            64 => self.target_cpu().write_register(reg_id, v as u64),
            _ => Ok(()),
        };

        match write_result {
            Ok(_) => Ok(()),
            Err(error) => {
                warn!(
                    "Client failed to write_register({:?}, {:?}): {}",
                    reg_id, val, error
                );
                Err(TargetError::NonFatal)
            }
        }
    }
}

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
        if let Some(xml_string) = self.proc.cpu.architecture().target_xml(annex) {
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
            let len_copy = input_len.min(output_len);

            // perform the memcpy
            let input_start = offset as usize;
            let input_end = input_start + len_copy;
            let dest_end = len_copy;

            buf[..dest_end].copy_from_slice(&b[input_start..input_end]);

            // return the number of bytes we actually copied
            Ok(len_copy)
        } else {
            Err(TargetError::NonFatal)
        }
    }
}

/// GDB breakpoints and watchpoints
/// The GDB commands for break points and watch points do not immediately cause
/// a remote serial protocol interaction. GDB only actually sets (break/watch)
/// points immediately before execution. the effective call flow is then:
/// 1. CPU is stopped
/// 2. User issues command to resume the CPU (next, step, continue, ...)
/// 3. Each (break/watch) point is sent to our implementation.
/// 4. The CPU executes
/// 5. ...
/// 6. The CPU finishes execution
/// 7. Break/watchpoints are cleared.
///
/// Also see note about this on [`struct TargetImpl`](TargetImpl).
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
        let addr = num_traits::ToPrimitive::to_u64(&addr).unwrap();

        info!("Client requested to add `{kind:?}` @ `{addr:08x?}`");
        // enforce only 1 breakpoint at a location
        if self.breakpoint_state.contains_active(&addr) {
            debug!("gdbserver already contains `{addr:08x?}`");
            return Ok(true);
        }

        // if we already have this breakpoint inserted into the
        // runtime, then re-activate it (even if we are at this current
        // address that is OK since we check for that in the breakpoint handler)
        if self.breakpoint_state.contains_deactive(&addr) {
            self.breakpoint_state.activate(&addr);
            debug!("gdbserver activated old bp @ `{addr:08x?}`");
            return Ok(true);
        }

        debug!("gdbserver is adding new breakpoint @ `{addr:08x?}`");
        // add code hook, propagate errors if necessary
        let bp_state = self.breakpoint_state.clone();
        match self
            .target_cpu()
            .code_hook(addr, addr, Box::new(GdbBreakpointHook(bp_state)))
        {
            Ok(hook_token) => {
                self.breakpoint_state.add_breakpoint(hook_token, addr);
                Ok(true)
            }
            Err(_) => {
                warn!("Failed to add breakpoint at `{:#x}`", addr);
                Ok(false)
            }
        }
    }

    /// Remove the breakpoint from `self.breakpoints`
    /// Return `Ok(false)` if the operation could not be completed
    fn remove_sw_breakpoint(
        &mut self,
        addr: GdbArchImpl::Usize,
        _kind: GdbArchImpl::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        if let Some(addr) = num_traits::ToPrimitive::to_u64(&addr) {
            trace!("gdb plugin deactivating breakpoint: {:#x}", addr);

            if self.breakpoint_state.deactivate(&addr) {
                return Ok(true);
                // Unfortunately we can't actually remove all breakpoints,
                // if pc is at the breakpoint, then the backend will explode, probably
                // TODO: remove non-same-pc breakpoints?
            } else {
                warn!("Could not find address: `{:#x}` in valid breakpoints", addr);
            }
        } else {
            warn!("Could not convert address to u64: `{:?}`", addr);
        }

        Ok(false)
    }
}

/// Cpu memory write callback - called when memory processor memory is written to.
/// The address and value are added to the [`MemHookCache`] belonging to the [`TargetImpl`]
/// to be later processed as a gdb `watchpoint` in
/// [step](fn@TargetImpl::step)
struct MemWrittenHook(Arc<MemHookCache>);
impl MemoryWriteHook for MemWrittenHook {
    fn call(
        &mut self,
        _proc: CoreHandle,
        address: u64,
        size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        debug!("Got mem write event for MemHookCache size `{size}` @ {address:#08x?}");
        let access = Access::from_target_write(address, size, data);
        self.0.add(address, access.val);
        Ok(())
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
    /// add the watchpoint to `self.watchpoints`.
    /// Return `Ok(false)` if the operation could not be completed
    fn add_hw_watchpoint(
        &mut self,
        addr: GdbArchImpl::Usize,
        _len: GdbArchImpl::Usize,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        let addr = num_traits::ToPrimitive::to_u64(&addr).unwrap();

        match kind {
            WatchKind::Write => {
                // make sure we're not already tracking the watchpoint
                if !self.mem_hook_cache.tracked(addr) {
                    let mem_cache = self.mem_hook_cache.clone();
                    return match self.target_cpu().mem_write_hook(
                        addr,
                        addr,
                        Box::new(MemWrittenHook(mem_cache)),
                    ) {
                        // successfully added target watchpoint
                        Ok(token) => {
                            self.mem_hook_cache.track(addr, token);
                            debug!("Added mem write hook for addr: {:#x}", addr);

                            // add if its not in the watchlist already
                            if !self.watchpoints.contains(&addr) {
                                self.watchpoints.push(addr);
                            }

                            // successfully added watchpoint
                            Ok(true)
                        }
                        // failed to add target watchpoint
                        Err(error) => {
                            warn!("Failed to add write watchpoint for {:#x}: {}", addr, error);

                            // failed to add watchpoint
                            Ok(false)
                        }
                    };
                }

                // already track this address
                Ok(true)
            }
            // TODO
            WatchKind::Read => Ok(false),      // not implemented yet
            WatchKind::ReadWrite => Ok(false), // not implemented yet
        }
    }

    /// Remove the watchpoint from `self.watchpoints`.
    /// Return `Ok(false)` if the operation could not be completed
    fn remove_hw_watchpoint(
        &mut self,
        addr: GdbArchImpl::Usize,
        len: GdbArchImpl::Usize,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        let addr = num_traits::ToPrimitive::to_u64(&addr).unwrap();
        let len = num_traits::ToPrimitive::to_u64(&len).unwrap();

        trace!("remove_hw_watchpoint(addr: {:#x}, size: {})", addr, len);

        // check the entire address range
        for addr in addr..(addr + len) {
            match self.watchpoints.iter().position(|x| *x == addr) {
                // check the next address if its not found
                None => continue,
                // found a match, so remove it and return success
                Some(pos) => {
                    _ = match kind {
                        WatchKind::Write => self.watchpoints.remove(pos),
                        WatchKind::Read => self.watchpoints.remove(pos),
                        WatchKind::ReadWrite => self.watchpoints.remove(pos),
                    };
                    if let Ok(hook) = self.mem_hook_cache.remove_hook(addr) {
                        self.target_cpu().delete_hook(hook).unwrap();
                    } else {
                        error!("Failed to remove memory watchpoint from CpuEngineBackend");
                    }

                    trace!("remove_hw_watchpoint: removed watchpoint");
                    return Ok(true);
                }
            }
        }

        trace!("remove_hw_watchpoint: failed to remove anything");
        // we did not remove anything
        Ok(false)
    }
}
