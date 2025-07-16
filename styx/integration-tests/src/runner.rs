// SPDX-License-Identifier: BSD-2-Clause
//! Defines [ProcessorIntegrationTest] and [run_test] for testing emulations
//! end-to-end with styx events.

#[cfg(feature = "factory")]
use emulation_service::processor_factory::ProcessorFactory;
#[cfg(feature = "factory")]
use styx_core::grpc::args::HasEmulationArgs;

use std::time::{Duration, Instant};
use styx_core::{
    grpc::args::Target,
    prelude::*,
    tracebus::{
        event_listener::{BufferedEventListener, ListenResult},
        TraceEventType, TraceableItem,
    },
};
use tokio_util::sync::CancellationToken;
use tracing::debug;

/// Use `ProcessorIntegrationTest` to run an integration test that is confirming
/// correctness by observing trace events. This should be used in conjunction
/// with [run_test].
pub struct ProcessorIntegrationTest {
    /// the target under test
    pub target: Target,
    /// the processor for the target
    pub processor: Processor,
    /// duration that the test (the processor) should run before stopping
    pub timeout: Duration,
    /// full path to the trace event file
    pub trace_path: String,
    /// event mask, use this to filter which events get buffered and returned
    /// by the event listener
    pub event_mask: TraceEventType,
}

impl ProcessorIntegrationTest {
    #[cfg(feature = "factory")]
    /// Make a new `ProcessorIntegrationTestor`
    pub fn new<T: HasEmulationArgs>(
        args: &T,
        run_duration: Duration,
        event_mask: TraceEventType,
    ) -> Self {
        use styx_core::executor::DefaultExecutor;

        let pp = ProcessorFactory::create_processor_no_svc(args, DefaultExecutor).unwrap();
        Self::from_proc(pp, args.target(), run_duration, event_mask)
    }

    /// Make a new `ProcessorIntegrationTestor` from an already built processor.
    pub fn from_proc(
        proc: Processor,
        target: Target,
        run_duration: Duration,
        event_mask: TraceEventType,
    ) -> Self {
        let trace_path = mkpath(None, SRB_TRACE_FILE_EXT);
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("STRACE_KEY", &trace_path) };
        Self {
            target,
            processor: proc,
            timeout: run_duration,
            trace_path,
            event_mask,
        }
    }

    /// Get the path to the styx trace file
    pub fn trace_path(&self) -> String {
        self.trace_path.clone()
    }

    /// Start the processor, return a `bool` that echos the Result received from
    /// starting the processor.
    pub fn start_processor(&mut self) -> bool {
        debug!("start processor");
        let result = self.processor.run(self.timeout);
        debug!("processor finished");
        result.is_ok()
    }

    /// Collect the events from the trace file being produced by processor
    /// - wait for the trace file
    /// - construct a [BufferedEventListener]
    /// - call the [consume](fn@BufferedEventListener::consume).
    ///
    /// Return a [ListenResult] which contains the events.
    pub fn collect_events(&self) -> ListenResult {
        // Read from the trace file. Wait some small amount of time for it
        // to be created, with a max time so that we don't wait forever
        const MAX_WAIT_TIME: Duration = Duration::from_secs(2);

        let finstant = Instant::now();
        loop {
            if std::path::Path::new(&self.trace_path).exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
            if finstant.elapsed() > MAX_WAIT_TIME {
                panic!("srb file has not been created")
            }
        }
        debug!("processing SRB file: {} ... ", &self.trace_path);

        let mut event_listener = BufferedEventListener::new(
            &self.trace_path,
            self.event_mask,
            Duration::from_millis(5),
            10,
            CancellationToken::new(),   // no cancellation token needed yet
            20,                         // re-try 20 times
            Duration::from_millis(100), // 100 ms between re-trues
        )
        .unwrap();
        // buffer the events
        let result = event_listener.consume();
        assert!(result.is_ok(), "no errors in listen result");
        let result = result.unwrap();
        debug!(
            "event_listener finishes, event count: {:?}",
            result.buffer.len()
        );
        result
    }
}

/// Run a test using the info in `ProcessorIntegrationTest`
pub fn run_test(testmeta: &mut ProcessorIntegrationTest) -> Vec<TraceableItem> {
    let result = testmeta.start_processor();
    assert!(result);

    let events = testmeta.collect_events();
    events.buffer.to_vec()
}
