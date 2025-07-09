// SPDX-License-Identifier: BSD-2-Clause
use derivative::Derivative;
#[cfg(feature = "tui")]
use libafl::monitors::tui::TuiMonitor;
#[cfg(not(feature = "tui"))]
use libafl::prelude::SimpleMonitor;
use libafl::{
    corpus::{CachedOnDiskCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{ExitKind, InProcessExecutor},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasMutatorBytes},
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    prelude::{AflMapFeedback, TimeoutFeedback},
    schedulers::QueueScheduler,
    stages::StdMutationalStage,
    state::StdState,
    Fuzzer, StdFuzzer,
};

use libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list};
use rustc_hash::FxHashMap;
use std::{any::Any, thread, time::Instant};
use std::{fs, marker::PhantomData};
use std::{path::PathBuf, time::Duration};
use styx_core::plugins::Plugins;
use styx_core::{
    cpu::ExecutionReport,
    tracebus::{
        BaseTraceEvent, IPCTracer, TraceProvider, TracerReader, TracerReaderOptions, STRACE,
    },
};
use styx_core::{executor::ExecutorImpl, prelude::*};
use styx_sync::{
    cell::UnsafeCell,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use thiserror::Error;
use tracing::{debug, warn};

#[derive(Debug, Error)]
pub enum StyxFuzzerError {
    #[error("Coverage map must be a power of 2, is: {0}")]
    BadCoverageMapSize(usize),
}

/// Provided a coverage map size, manages the internal pointer to coverage map,
/// and dishes out unchecked pointers to any consumers
///
/// # Safety
/// In order for styx to give afl access to the coverage map data, and allow
/// the harness post-exec hook to process and then update the coverage map
/// based on the styx-trace output we need to have 2 `&mut` to the internal
/// coverage map.
///
/// The only valid ways to consume this data are to either immediately hand
/// off the mutable ref to afl, or to pass it into the post-processing thread.
///
/// The latter *must* synchronize access to operating on the coverage map only
/// while afl is not operating on it (eg. while a "running flag" is set and before
/// you tell afl "im done processing this exec" is set)
#[derive(Debug)]
struct CoverageMap<'a> {
    buffer: UnsafeCell<Vec<u8>>,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> CoverageMap<'a> {
    /// Creates a new [`CoverageMap`] of the desired size
    fn new(size: usize) -> Self {
        Self {
            buffer: UnsafeCell::new(vec![0; size]),
            _lifetime: PhantomData,
        }
    }

    /// Gets a new slice from the internal coverage map data listing
    ///
    /// The returned slice has the same lifetime as `self`, so the reference
    /// (even though retrieved via `unsafe` means) in theory will not outlive
    /// the owning [`CoverageMap`].
    ///
    /// This previous statement will of course be invalidated if you
    /// start making everything `'static` when things aren't
    ///
    /// # Safety
    /// This provides unsynchronized access to the internal coverage map
    /// listing. Thar be dragons.
    unsafe fn get_coverage_map_mut(&self) -> &'a mut [u8] {
        let cov_map = &mut self.buffer.with_mut(|b| unsafe { &mut *b });
        let bare = cov_map.as_mut_ptr();

        unsafe { std::slice::from_raw_parts_mut(bare, cov_map.len()) }
    }
}

/// The type of input to use for the fuzzer
///
/// If `Grammar(String)` is used, then the string should be a path to a grammar file
/// that can be used to generate inputs for the specific `Genrator` that is being used.
///
/// **NOTE**: The `Grammar` variant is only used with a custom fuzz function
/// for the [`StyxFuzzerConfig`], otherwise you will get a runtime error.
///
/// Contributions appreciated to add support for grammar-based inputs in a more
/// generic fashion
#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Hash, Clone)]
pub enum StyxFuzzerInputType {
    #[default]
    RandomBytes,
    RandomPrintable,
    Grammar(String),
}

/// Fuzzer Configuration to use while fuzzing the target program
#[derive(Derivative)]
#[derivative(Debug)]
pub struct StyxFuzzerConfig {
    /// Timeout for fuzzing executions
    pub timeout: Duration,
    /// Timeout on max instructions, if true then the fuzzer will
    /// exit with timeout when the maximum number of instructions
    /// has been executed.
    ///
    /// If false then the fuzzer will continue to run until
    /// the time-based timeout is reached.
    pub timeout_on_max_insns: bool,
    /// Path to file containing branch information, after running GetBranches.java in ghidra
    pub branches_filepath: String,
    /// Addresses at which to exit emulation
    pub exits: Vec<u64>,
    /// Maximum number of instructions to execute per fuzzing run
    pub max_insns: u64,
    /// Max input length
    pub max_input_len: usize,
    /// By default the fuzzer just writes inputs into memory at the location specified
    /// in this config.  If other target specific actions need to be taken when inserting
    /// inputs (like setting the value of a register) then a custom function should be
    /// provided.
    #[derivative(Debug = "ignore")]
    pub input_hook: InputCallbackType,
    /// Pre-fuzzing setup
    #[derivative(Debug = "ignore")]
    pub setup: SetupCallbackType,
    /// Function for saving context
    #[derivative(Debug = "ignore")]
    pub context_save: ContextSaveCallbackType,
    /// Function for restoring context
    #[derivative(Debug = "ignore")]
    pub context_restore: ContextRestoreCBType,
    /// Directory to use for the discovered crashes,
    /// defaults to `./crashes`
    pub crashes_dir: PathBuf,
    /// Paths to any **read-only** input corpora not in [`Self::crashes_dir`]
    ///
    /// **NOTE**: Any path added here is *read-only* and will
    /// not be modified at runtime
    pub corpus_paths: Vec<PathBuf>,
    /// Input generator to use, defaults to `StyxFuzzerInputType::RandomBytes`.
    ///
    /// **NOTE**: If you want to use an input generator that is not `RandomBytes`,
    /// you must provide a custom fuzzer function via [`Self::fuzz_func`]. This is
    /// due to a limitation of the underlying fuzzing library (LibAFL) which requires
    /// the input generator (and essentially everything else) to be known at compile time.
    ///
    /// If you want to use a grammar-based input generator, you should
    /// set this to `StyxFuzzerInputType::Grammar(String)` with the
    /// grammar string being the path to the grammar file. You can then
    /// convert that into the proper grammar type in your custom fuzzer function
    /// before beginning execution.
    pub generator: StyxFuzzerInputType,
    /// Execution stride, how many instructions to execute per call to `execute`
    ///
    /// This should not be a large number (Default is 1000).
    pub execution_stride: u64,
    /// Maximum number of inputs fuzz cases and reasons
    /// to keep in an in-memory cache
    pub max_in_mem_corpus: u64,
    /// Optional custom fuzzer function to use instead of the default
    #[derivative(Debug = "ignore")]
    pub fuzz_func: Option<FuzzerFuncType>,
}

impl Default for StyxFuzzerConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(1),
            timeout_on_max_insns: true,
            branches_filepath: String::from("./branches.txt"),
            exits: vec![],
            max_insns: 100_000,
            max_input_len: 0,
            input_hook: Box::new(|_, _| true),
            setup: Box::new(|_| ()),
            context_save: Box::new(|_| Arc::new(())),
            context_restore: Box::new(|_, _| ()),
            corpus_paths: Vec::new(),
            crashes_dir: PathBuf::from("./crashes"),
            generator: StyxFuzzerInputType::default(),
            execution_stride: 1000,
            max_in_mem_corpus: 100,
            fuzz_func: None,
        }
    }
}

// typedefs to appease clippy
type AnyTpe = Arc<dyn Any + Send>;
type InputCallbackType = Box<dyn Fn(&mut ProcessorCore, &[u8]) -> bool>;
type SetupCallbackType = Box<dyn Fn(&mut ProcessorCore)>;
type ContextSaveCallbackType = Box<dyn Fn(&mut ProcessorCore) -> AnyTpe>;
type ContextRestoreCBType = Box<dyn Fn(&mut ProcessorCore, AnyTpe)>;
type FuzzerFuncType =
    Box<dyn Fn(&mut FuzzerExecutor, &mut ProcessorCore) -> Result<(), UnknownError>>;

unsafe impl Send for StyxFuzzerConfig {}
unsafe impl Sync for StyxFuzzerConfig {}

/// The main fuzzer plugin
///
/// In order to properly construct this plugin you must provide a
/// size of the coverage map that the plugin can use to share with the
/// AFL harness and the styx-trace consumers can update.
///
/// The processor needs to have a StyxTracePlugin attached to it, with
/// only block trace events enabled.
///
/// When run, the plugin will first call the user-provided `config.setup` function
/// which is intended to be used to get emulation into the state where fuzzing can
/// begin. For example, the setup function could spin up a UART client, send some
/// data to the target, then emulate up until some interesting function in the target.
///
/// After running the setup function, the plugin creates a bunch of LibAFL structs
/// and then starts fuzzing.
///
/// The user provides functions to save/restore emulation state between fuzzing
/// runs, make these as small/fast as possible because they get called frequently.
/// Same deal with the insert_input function
///
/// Example usage:
/// ```no_run
/// # use styx_emulator::loader::RawLoader;
/// # use styx_emulator::processors::arm::kinetis21::Kinetis21Builder;
/// # use styx_emulator::plugins::styx_trace::StyxTracePlugin;
/// # use styx_emulator::prelude::*;
/// # use styx_emulator::sync::Arc;
/// # use styx_emulator::arch::arm::ArmVariants;
/// # use std::time::Duration;
/// # use std::any::Any;
/// # use styx_emulator::plugins::fuzzer::{FuzzerExecutor, StyxFuzzerConfig};
///
/// // needs to be a power of 2
/// const COVERAGE_MAP_SIZE: usize = 1024;
///
/// const MAX_INPUT_LEN: usize = 5;
///
/// let pre_fuzzing_setup = |proc: &mut ProcessorCore| {
///     // do setup things
/// };
/// let context_save = |proc: &mut ProcessorCore| -> Arc<dyn Any + Send> {
///     // save state
///     # Arc::new(())
/// };
/// let context_restore = |proc: &mut ProcessorCore, data: Arc<dyn Any + Send>| {
///     // restore state
/// };
/// let insert_input = |proc: &mut ProcessorCore, data: &[u8]| -> bool {
///     // insert input
///     # true
/// };
/// let mut proc = ProcessorBuilder::default()
///     .with_builder(Kinetis21Builder::default())
///     .with_backend(Backend::Unicorn)
///     .with_executor(FuzzerExecutor::new(
///         COVERAGE_MAP_SIZE,
///         StyxFuzzerConfig {
///             timeout: Duration::from_secs(1),
///             branches_filepath: String::from("./branches.txt"),
///             exits: vec![0xba2],
///             max_input_len: MAX_INPUT_LEN,
///             input_hook: Box::new(insert_input),
///             setup: Box::new(pre_fuzzing_setup),
///             context_restore: Box::new(context_restore),
///             context_save: Box::new(context_save),
///             ..Default::default()
///         },
///     ))
///     .add_plugin(StyxTracePlugin::new(false, false, false, true))
///     .with_loader(RawLoader)
///     .with_target_program(String::from("path_to_program"))
///     .build().unwrap();
///
/// // proc.run(Forever)?;
/// ```
#[derive(Debug)]
pub struct FuzzerExecutor<'a> {
    config: StyxFuzzerConfig,
    coverage_map: CoverageMap<'a>,
}

impl FuzzerExecutor<'static> {
    /// Makes a new [`FuzzerExecutor`] provided a [`CoverageMap`] size
    /// to use for IPC between the styx trace targeting and the AFL harness
    pub fn new(coverage_map_size: usize, config: StyxFuzzerConfig) -> Self {
        Self {
            config,
            coverage_map: CoverageMap::new(coverage_map_size),
        }
    }

    /// Takes in a file with a list of all basic block start addresses and loads
    /// the entries into a hashmap to be used as a lookup table
    fn load_branches_from_file(&self) -> FxHashMap<u32, usize> {
        let mut hashmap = FxHashMap::default();

        let contents = fs::read_to_string(&self.config.branches_filepath).unwrap();

        for (i, line) in contents.lines().enumerate() {
            let addr = line.trim().parse::<u32>().unwrap();
            hashmap.insert(addr, i);
        }

        hashmap
    }

    /// Performs initial, pre-fuzzing emulation up to a target address
    /// (if specified in the config) before performing a cpu context save
    /// to create a restore point for fuzzing
    fn fuzzer_setup(&self, proc: &mut ProcessorCore) {
        let stop_emulation = |cpu: CoreHandle<'_>| {
            cpu.cpu.stop();
            Ok(())
        };

        // adds hooks to stop emulation if we hit any of the exit points specified in the config
        for exit in &self.config.exits {
            debug!("adding exit hook at: [0x{:x},0x{:x})", *exit, *exit + 1);
            proc.cpu
                .code_hook(*exit, *exit + 1, Box::new(stop_emulation))
                .unwrap();
        }
    }

    /// This function first clears any existing events from the ring buffer,
    /// then spawns a thread to process trace events and update the coverage map
    /// `emulation_running`
    /// - set to true upon entering the fuzzer harness function
    /// - set to false once emulation finishes in the fuzzer harness function
    ///   `done_processing`
    /// - set to true if the ring buffer is empty (when we receive a None)
    /// - set to false before receiving a trace event
    /// - the fuzzer harness function waits to return until this is true
    fn capture_trace_events(
        &self,
        emulation_running: Arc<AtomicBool>,
        done_processing: Arc<AtomicBool>,
        branches: FxHashMap<u32, usize>,
    ) {
        let opts = TracerReaderOptions::new(&STRACE.key());
        let mut rx = IPCTracer::get_consumer(opts.clone()).unwrap();

        // drain the trace bus because we want this to block the main thread so
        // that we make sure the buffer is empty before starting any fuzzing runs
        loop {
            let evt = rx.zero_copy_context().try_recv::<BaseTraceEvent>().unwrap();
            if evt.is_none() {
                break;
            }
        }

        // prep the variables for the trace processing + updating of the
        // coverage map
        done_processing.store(true, Ordering::Release);
        let coverage_map = unsafe { self.coverage_map.get_coverage_map_mut() };

        // start the worker thread to process trace events forever
        thread::spawn(move || {
            loop {
                // if emulation is not running don't start processing
                //
                // - emulation must be running for there to be any events
                // - we need to be done processing the events to start processing
                if !emulation_running.load(Ordering::Acquire)
                    && done_processing.load(Ordering::Acquire)
                {
                    continue;
                }

                // signal the other thread that we are beginning to process data
                done_processing.store(false, Ordering::Release);
                let evt = rx.zero_copy_context().try_recv::<BaseTraceEvent>().unwrap();

                // all events have `pc` attached, so do a lookup for
                // pc to see if it's in our branch map, and get the coverage
                // map index to update if so
                if let Some(e) = evt {
                    if let Some(v) = branches.get(&e.pc) {
                        // update the coverage index
                        //
                        // This is roughly whats happening in the counters in afl++
                        // See: https://github.com/AFLplusplus/AFLplusplus/blob/ea14f3fd40e32234989043a525e3853fcb33c1b6/instrumentation/afl-compiler-rt.o.c#L179
                        coverage_map[*v] = coverage_map[*v].wrapping_add(1);
                    }
                }

                // done processing the event, so signal
                done_processing.store(true, Ordering::Release);
            }
        });
    }

    /// Takes an input, inserts the input in memory, runs the emulation,
    /// converts the styx exit status into the libafl exit status,
    /// waits for the background thread to finish processing trace events
    #[inline]
    fn harness_fn(
        &self,
        proc: &mut ProcessorCore,
        input: &BytesInput,
        running: Arc<AtomicBool>,
        done_processing: Arc<AtomicBool>,
        saved_context: AnyTpe,
    ) -> ExitKind {
        // signal that we're about to start executing the target
        running.store(true, Ordering::Release);
        if !(self.config.input_hook)(proc, input.bytes()) {
            warn!("insert input failed");
            return ExitKind::Ok;
        }

        let mut execution_report: ExecutionReport;

        let timeout = Instant::now() + self.config.timeout;

        // run the target program until the timout is reached unless an error
        let mut total_insn_exec = 0;
        loop {
            execution_report = proc
                .cpu
                .execute(
                    &mut proc.mmu,
                    &mut proc.event_controller,
                    self.config.execution_stride,
                )
                .unwrap();
            let reason = &execution_report.exit_reason;

            // increase the total instruction count
            total_insn_exec += self.config.execution_stride;

            // something is broken or the host requested a stop
            if reason.fatal() || reason.is_stop_request() {
                break;
            }

            // check if we timed out on total insn count
            if total_insn_exec >= self.config.max_insns {
                // user configurable option. depending on the target
                // it is not usefule to trigger an objective on the
                // total insn count and instead let it run until the
                // time-based timeout is reached
                if self.config.timeout_on_max_insns {
                    execution_report.exit_reason = TargetExitReason::ExecutionTimeoutComplete;
                }
                break;
            }

            // check if 'now' is after the timeout
            if timeout < Instant::now() {
                execution_report.exit_reason = TargetExitReason::ExecutionTimeoutComplete;
                break;
            }

            proc.event_controller
                .next(proc.cpu.as_mut(), &mut proc.mmu)
                .unwrap();
        }

        let reason = &execution_report.exit_reason;
        // check the [`TargetExitReason`]
        let exit_kind = if reason.fatal() {
            match reason {
                TargetExitReason::InvalidStateFromHost(_) => ExitKind::Ok,
                TargetExitReason::InvalidStateFromTarget(_) => ExitKind::Ok,
                _ => ExitKind::Crash,
            }
        } else {
            match reason {
                TargetExitReason::ExecutionTimeoutComplete => ExitKind::Timeout,
                _ => ExitKind::Ok,
            }
        };

        // target is done running
        running.store(false, Ordering::Release);

        // call the context restore now that the target is done running
        (self.config.context_restore)(proc, saved_context);

        // wait until the processing task is done
        loop {
            if done_processing.load(Ordering::Acquire) {
                break;
            }
        }

        exit_kind
    }

    /// the main fuzzing function
    fn libafl_fuzz(&mut self, proc: &mut ProcessorCore) -> Result<(), UnknownError> {
        let branches = self.load_branches_from_file();

        // Setup the fuzzing context + runtime
        // - call the user provided function for pre-fuzzing setup
        // - perform initial fuzzer reachability setup
        // - save the context to restore to between emulation runs
        self.config.setup.as_ref()(proc);
        self.fuzzer_setup(proc);
        let saved_cpu_context = (self.config.context_save)(proc);

        // initialize observers
        // - execution timing
        // - coverage map
        let time_observer = TimeObserver::new("time");
        let coverage_observer = unsafe {
            HitcountsMapObserver::new(StdMapObserver::new(
                "coverage map",
                self.coverage_map.get_coverage_map_mut(),
            ))
        };
        let coverage_observer = coverage_observer.track_indices().track_novelties();

        // Feedback to rate the interestingness of an input.
        let mut feedback = feedback_or!(
            MaxMapFeedback::new(&coverage_observer),
            TimeFeedback::new(&time_observer),
            AflMapFeedback::new(&coverage_observer),
        );

        // The Monitor trait defines how the fuzzer stats are displayed to the user
        #[cfg(not(feature = "tui"))]
        let mon = SimpleMonitor::new(|s| println!("{s}"));
        #[cfg(feature = "tui")]
        let mon = TuiMonitor::builder()
            .title("Styx-LibAFL Fuzzer")
            .enhanced_graphics(true)
            .build();

        // The event manager handles the various events generated during the fuzzing loop
        // such as the notification of the addition of a new item to the corpus
        let mut event_mgr = SimpleEventManager::new(mon);

        // a simple FIFO scheduler
        let scheduler = QueueScheduler::new();

        // A feedback to detect crashes.
        let mut objective = feedback_or!(CrashFeedback::new(), TimeoutFeedback::new());

        // holds fuzzer state such as current input corpus, crashes, etc.
        let mut state = StdState::new(
            StdRand::with_seed(current_nanos()),
            CachedOnDiskCorpus::new(
                &self.config.crashes_dir,
                self.config.max_in_mem_corpus as usize,
            )
            .unwrap(),
            OnDiskCorpus::new(&self.config.crashes_dir).unwrap(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // these atomics control the capturing of trace events
        let running: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let done_processing: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        // spawns a thread to read trace events, atomics get shared between the fuzzer harness and this new thread
        self.capture_trace_events(running.clone(), done_processing.clone(), branches);

        // make sure that the trace buffer is empty before beginning,
        // `self.capture_trace_events` should block on draining
        // the trace buffer before we get here
        assert!(done_processing.load(Ordering::Acquire));

        // this closure takes in an input and returns an ExitKind depending on the exit state of the emulation
        // it also invokes the trace event reciever which updates the observed coverage map
        let mut harness = |input: &BytesInput| {
            // call the harness function
            self.harness_fn(
                proc,
                input,
                running.clone(),
                done_processing.clone(),
                saved_cpu_context.clone(),
            )
        };

        // prepare for actual fuzz case execution
        let mut generator = RandBytesGenerator::new(self.config.max_input_len);
        let mut executor = InProcessExecutor::with_timeout(
            &mut harness,
            tuple_list!(time_observer, coverage_observer),
            &mut fuzzer,
            &mut state,
            &mut event_mgr,
            self.config.timeout,
        )
        .expect("Failed to create executor.");

        // Generate 8 initial inputs
        state
            .generate_initial_inputs(
                &mut fuzzer,
                &mut executor,
                &mut generator,
                &mut event_mgr,
                8,
            )
            .expect("Failed to generate the initial corpus");

        // the input paths are the "read only" corpus paths and the crashes directory
        let mut input_paths = vec![self.config.crashes_dir.clone()];
        input_paths.extend(self.config.corpus_paths.iter().cloned());

        // Reuse any inputs from existing corpus
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut event_mgr, &input_paths)
            .expect("Failed to load initial inputs from corpus");

        // Setup a mutational stage with a basic bytes mutator
        let mutator = StdScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        // run the fuzzer loop
        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut event_mgr)
            .with_context(|| "Error in the fuzzing loop")
    }
}

impl ExecutorImpl for FuzzerExecutor<'static> {
    fn emulation_setup(
        &mut self,
        proc: &mut ProcessorCore,
        _plugins: &mut Plugins,
    ) -> Result<(), UnknownError> {
        match self.config.fuzz_func {
            Some(_) => {
                // if the user provided a custom fuzz function, we use that
                let func = std::mem::take(&mut self.config.fuzz_func).unwrap();
                func(self, proc)?;

                // replace the fuzz function
                self.config.fuzz_func = Some(func);
            }
            None => {
                // otherwise we use the default fuzz executor function
                self.libafl_fuzz(proc)?;
            }
        }

        Ok(())
    }

    fn valid_emulation_conditions(&mut self, _proc: &mut ProcessorCore) -> bool {
        false
    }
}
