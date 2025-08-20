// SPDX-License-Identifier: BSD-2-Clause
//! Provides a number of plugins useful for logging and
//! introspection into the execution of emulators.
//!
//! Not to be confused with `styx-trace`.
//!
//! These plugins utilize the [`mod@tracing`] library to log
//! messages for different subsystems and report metrics and
//! interrupt execution spans to observability infrastructure
//! in order to aid quick debugging, profiling, and insight
//! into the execution peculiarites of emulators.
//!
//! There are a few different flavors of tracing plugins
//! included here:
//!
//! NOTE: The default tracing plugin, [`ProcessorTracingPlugin`], MUST
//! be enabled in order for other trace plugins to function.
//!
//! # Default plugins
//! - [`ProcessorTracingPlugin`]
//!     - always enabled
//!     - provides an avenue for all the other tracing plugins
//!       to exist
//!     - logs `styx` tracing message at `info` and above by default
//!
//! # Emulation validation
//! - [`JsonMemoryReadPlugin`]
//! - [`JsonMemoryWritePlugin`]
//! - [`JsonPcTracePlugin`]
//! - [`JsonInterruptPlugin`]
//!
//! # Backend Introspection
//! - [`TokioConsolePlugin`] - connectes to tokio console
//!     - useful for debugging and monitoring the [`Processor`]'s
//!       tokio runtime
//! - [`OtlpStreamingPlugin`] - Streams execution spans to an OTLP backend
//!     - configurable with environment variables
//!     - generally used to monitor / debug event controller hot paths
//! - [`TracyProfilerPlugin`] - stream data to a tracy profiler
//!     - READ THE PLUGIN DOCS BEFORE USING
//!     - The default configuration may not be what you want
//!     - Must enable feature `tracy`
//!
//!  # Crate features
//!  ### Tracing features
//!  - **tracy**
//!     - When enabled, use [`tracing-tracy`](https://docs.rs/tracing-tracy/latest/tracing_tracy/)
//!       to collect [`Tracy`](https://docs.rs/tracing-tracy/latest/tracing_tracy/) profiles.
//!     - Must be enabled to use [`TracyProfilerPlugin`]
use anyhow::Context;
use opentelemetry::trace::TracerProvider as _;
use styx_core::hooks::StyxHook;
use tracing::{trace, Level};
use tracing_subscriber::layer::Layer;
use tracing_subscriber::{filter, prelude::*, EnvFilter, Registry};

use styx_core::prelude::*;
use styx_sync::lazy_static;
use styx_sync::sync::{Arc, Mutex};

type BoxedLayer<S> = Box<dyn Layer<S> + Send + Sync>;

lazy_static! {
    /// # lazy-static
    /// This is allowed to be a lazy static purely for the reason that the
    /// underlying [`tracing`] engine is also running via lazy static and
    /// that cannot change. That makes each [`TracingLayersList`] get
    /// elevated to the static level anyways
    static ref TRACING_LAYERS: TracingLayersList = TracingLayersList::default();
}

/// Used as a local static to control the invocation of the global
/// [`tracing_subscriber`] instance.
#[derive(Default)]
struct TracingLayersList {
    layers: Arc<Mutex<Vec<BoxedLayer<Registry>>>>,
}

impl TracingLayersList {
    fn push(&self, layer: BoxedLayer<Registry>) {
        self.layers.lock().unwrap().push(layer);
    }

    fn init(&self) {
        let new = {
            let mut layers = self.layers.lock().unwrap();

            let new: Vec<BoxedLayer<Registry>> = (*layers).drain(0..).collect();
            new
        };

        // build our registry
        let registry = tracing_subscriber::registry();
        let registry = registry.with(new);
        registry.init()
    }
}

/// The default tracing plugin, no trace messages (no matter what other
/// plugins you choose) will be logged if this plugin is not enabled.
#[derive(Debug, Default)]
pub struct ProcessorTracingPlugin;

styx_uconf::register_component!(register plugin: id = tracing, component = ProcessorTracingPlugin);

impl Plugin for ProcessorTracingPlugin {
    fn name(&self) -> &str {
        "tracing"
    }

    /// Now that all the plugins have added the desired logging to the layers,
    /// initialize the global default logging
    fn plugins_initialized_hook(
        &mut self,
        _proc: &mut BuildingProcessor,
    ) -> Result<(), UnknownError> {
        TRACING_LAYERS.init();
        Ok(())
    }
}

impl UninitPlugin for ProcessorTracingPlugin {
    /// Adds the default tracing items to the local static layers
    fn init(
        self: Box<Self>,
        _proc: &mut BuildingProcessor,
    ) -> Result<Box<dyn Plugin>, UnknownError> {
        // log everything at `info` or above
        TRACING_LAYERS.push(Box::new(
            tracing_subscriber::fmt::layer()
                .with_level(true)
                .with_target(false)
                .without_time()
                .compact()
                .with_filter(
                    EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("info"))?,
                ),
        ));

        Ok(self)
    }
}

/// Simple logging plugin for any styx machine that uses a tokio runtime.
///
/// These plugin enables the use of the tool `tokio-console`, which can
/// be installed via `cargo install --locked tokio-console`. This tool
/// allows you to peek a little inside of the tokio runtime and inspect:
/// - orphaned tasks
/// - poll rate of tasks
/// - task status
/// - worker status
///
/// and most importantly, it gives you *pretty pictures* **ohhhhhhhhh**.
///
/// use this in your machine by adding it as a plugin to your [`Processor`]
///
/// NOTE: The default tracing plugin, [`ProcessorTracingPlugin`], MUST
/// be enabled in order for other trace plugins to function.
#[derive(Debug, Default)]
pub struct TokioConsolePlugin;

impl Plugin for TokioConsolePlugin {
    fn name(&self) -> &str {
        "tokio-console"
    }
}

impl UninitPlugin for TokioConsolePlugin {
    fn init(
        self: Box<Self>,
        _proc: &mut BuildingProcessor,
    ) -> Result<Box<dyn Plugin>, UnknownError> {
        // add a filter layer that only applies to the necessary targets for tokio-console
        TRACING_LAYERS.push(Box::new(
            console_subscriber::ConsoleLayer::builder()
                .with_default_env()
                .spawn(),
        ));

        Ok(self)
    }
}

styx_uconf::register_component!(register plugin: id = tokio_console, component = TokioConsolePlugin);

/// Enables streaming OTLP telemetry data to an endpoint like grafana or
/// prometheus. Controlled through environment variables `OTEL_*` as a part
/// of the upstream opentelemetry crates, defaults to the common opentelemetry
/// local host setup + default port (collector endpoint on `localhost:4317`).
///
/// ## Upstream Documentation
/// - [opentelemetry-otlp](https://docs.rs/opentelemetry-otlp/latest/opentelemetry_otlp/)
/// - [opentelemetry-rust](https://opentelemetry.io/docs/instrumentation/rust/)
/// - [tracing-opentelemetry](https://docs.rs/tracing-opentelemetry/0.19.0/tracing_opentelemetry/)
///
/// ## Word of Caution
///
/// It is highly unreccommended to use jaeger unless you like
/// crashes, DOS etc. We have made a lot of choices to reduce the reported
/// trace spans so that collectors are able to handle stuff, but jaeger has been
/// known to crash, and at the very least go completely unresponsive
///
/// NOTE: The default tracing plugin, [`ProcessorTracingPlugin`], MUST
/// be enabled in order for other trace plugins to function.
#[derive(Debug, Default)]
pub struct OtlpStreamingPlugin;

impl Plugin for OtlpStreamingPlugin {
    fn name(&self) -> &str {
        "OTLP-streaming"
    }
}

impl UninitPlugin for OtlpStreamingPlugin {
    fn init(
        self: Box<Self>,
        _proc: &mut BuildingProcessor,
    ) -> Result<Box<dyn Plugin>, UnknownError> {
        // otlp layer
        TRACING_LAYERS.push(Box::new(
            tracing_opentelemetry::layer().with_tracer(
                opentelemetry_otlp::new_pipeline()
                    .tracing()
                    .with_exporter(opentelemetry_otlp::new_exporter().tonic())
                    .with_trace_config(
                        opentelemetry_sdk::trace::Config::default().with_max_events_per_span(1024),
                    )
                    .install_batch(opentelemetry_sdk::runtime::Tokio)
                    .with_context(|| "Failed to make tonic OTLP tracer")?
                    .tracer("styx-emulator"),
            ),
        ));
        Ok(self)
    }
}

styx_uconf::register_component!(register plugin: id = otlp_streaming, component = OtlpStreamingPlugin);

fn pc_trace_hook(proc: CoreHandle) -> Result<(), UnknownError> {
    trace!(target: "pc-trace","{{\"type\": \"pc\", \"value\": \"{:#x}\"}}", proc.cpu.pc()?);
    Ok(())
}

/// Logs every single executed instruction address to the console in a
/// JSON compatible message.
///
/// There is a runtime cost associated with using this, buyer beware.
/// The schema of the messages follows:
///
/// ```json
/// {
///     "type": "pc",
///     "value": 41414141,
/// }
/// ```
///
/// NOTE: The default tracing plugin, [`ProcessorTracingPlugin`], MUST
/// be enabled in order for other trace plugins to function.
#[derive(Debug, Default)]
pub struct JsonPcTracePlugin;

impl Plugin for JsonPcTracePlugin {
    fn name(&self) -> &str {
        "JSON-pc"
    }
}

impl UninitPlugin for JsonPcTracePlugin {
    fn init(
        self: Box<Self>,
        proc: &mut BuildingProcessor,
    ) -> Result<Box<dyn Plugin>, UnknownError> {
        // add event hook
        proc.core.cpu.add_hook(StyxHook::code(.., pc_trace_hook))?;

        // enable the logging
        TRACING_LAYERS.push(Box::new(
            tracing_subscriber::fmt::layer()
                .compact()
                .without_time()
                .with_filter(filter::Targets::new().with_target("pc-trace", Level::TRACE)),
        ));
        Ok(self)
    }
}

styx_uconf::register_component!(register plugin: id = json_pc_trace, component = JsonPcTracePlugin);

/// Logs a json compatible message for every `memory write` event
fn write_memory_hook(
    proc: CoreHandle,
    address: u64,
    size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let value: Vec<u8> = data[0..size as usize].into();

    trace!(
        target: "write-memory",
        "{{\"type\": \"mem_write\", \"pc\": \"{:x}\", \"address\": \"{:x}\", \"size\": {}, \"data\": {:?}}}",
        proc.cpu.pc()?,
        address,
        size,
        value,
    );
    Ok(())
}

/// Logs every single target memory write to the console in a JSON compatible message.
///
/// There is a runtime cost associated with using this, buyer beware.
/// The schema of the messages follows:
///
/// ```json
/// {
///     "type": "mem_write",
///     "pc": 41414141,
///     "address": 42424242,
///     "size": 4,
///     "data": [65, 66, 67, 68]
/// }
/// ```
///
/// NOTE: The default tracing plugin, [`ProcessorTracingPlugin`], MUST
/// be enabled in order for other trace plugins to function.
#[derive(Debug, Default)]
pub struct JsonMemoryWritePlugin;

impl Plugin for JsonMemoryWritePlugin {
    fn name(&self) -> &str {
        "JSON Memory Write"
    }
}

impl UninitPlugin for JsonMemoryWritePlugin {
    fn init(
        self: Box<Self>,
        proc: &mut BuildingProcessor,
    ) -> Result<Box<dyn Plugin>, UnknownError> {
        // add event hook
        proc.core
            .cpu
            .add_hook(StyxHook::memory_write(.., write_memory_hook))?;

        // enable the logging
        TRACING_LAYERS.push(Box::new(
            tracing_subscriber::fmt::layer()
                .compact()
                .without_time()
                .with_filter(filter::Targets::new().with_target("write-memory", Level::TRACE)),
        ));
        Ok(self)
    }
}

styx_uconf::register_component!(register plugin: id = json_memory_write, component = JsonMemoryWritePlugin);

/// Logs every single target memory read to the console in a JSON compatible message.
///
/// There is a runtime cost associated with using this, buyer beware.
/// The schema of the messages follows:
///
/// ```json
/// {
///     "type": "mem_read",
///     "pc": 41414141,
///     "address": 42424242,
///     "size": 4,
///     "data": [65, 66, 67, 68]
/// }
/// ```
///
/// NOTE: The default tracing plugin, [`ProcessorTracingPlugin`], MUST
/// be enabled in order for other trace plugins to function.
#[derive(Debug, Default)]
pub struct JsonMemoryReadPlugin;

fn read_memory_hook(
    proc: CoreHandle,
    address: u64,
    size: u32,
    data: &mut [u8],
) -> Result<(), UnknownError> {
    tracing::trace!(
        target: "memory-read",
        "{{\"type\": \"mem_read\", \"pc\": \"{:x}\", \"address\": \"{:x}\", \"size\": {}, \"data\": {:?}}}",
        proc.cpu.pc()?,
        address,
        size,
        data
    );
    Ok(())
}

impl Plugin for JsonMemoryReadPlugin {
    fn name(&self) -> &str {
        "JSON Memory Read"
    }
}

impl UninitPlugin for JsonMemoryReadPlugin {
    fn init(
        self: Box<Self>,
        proc: &mut BuildingProcessor,
    ) -> Result<Box<dyn Plugin>, UnknownError> {
        // add event hook
        proc.core
            .cpu
            .add_hook(StyxHook::memory_read(.., read_memory_hook))?;

        // enable the logging
        TRACING_LAYERS.push(Box::new(
            tracing_subscriber::fmt::layer()
                .compact()
                .without_time()
                .with_filter(filter::Targets::new().with_target("memory-read", Level::TRACE)),
        ));
        Ok(self)
    }
}

styx_uconf::register_component!(register plugin: id = json_memory_read, component = JsonMemoryReadPlugin);

/// Enables console dumping of the interrupt TRACE events.
///
/// The fidelity of messages will be different from event controller
/// to event controller, PR's welcome.
///
/// NOTE: The default tracing plugin, [`ProcessorTracingPlugin`], MUST
/// be enabled in order for other trace plugins to function.
#[derive(Debug, Default)]
pub struct JsonInterruptPlugin;

impl Plugin for JsonInterruptPlugin {
    fn name(&self) -> &str {
        "JSON Interrupt"
    }
}

impl UninitPlugin for JsonInterruptPlugin {
    fn init(
        self: Box<Self>,
        _proc: &mut BuildingProcessor,
    ) -> Result<Box<dyn Plugin>, UnknownError> {
        // enable the logging
        TRACING_LAYERS.push(Box::new(
            tracing_subscriber::fmt::layer()
                .compact()
                .without_time()
                .with_filter(filter::Targets::new().with_target("interrupt", Level::TRACE)),
        ));
        Ok(self)
    }
}

styx_uconf::register_component!(register plugin: id = json_interrupt, component = JsonInterruptPlugin);

/// Enables support for the [Tracy](https://github.com/wolfpld/tracy) profiler.
///
/// - The feature **tracy** must be enabled.
///
/// Note: to get fancier `tracy` support you'll need to instrument just the
/// things you want via the `tracy-client` crate.
///
/// # A note on defaults
/// By default the `tracing-tracy` library enables the `broadcast` flag. We do
/// not, we also do not enable call-stack recording by default (see
/// [this](https://github.com/nagisa/rust_tracy_client/issues/42) issue for more).
///
/// If there are default option you want, change them via `RUST_FLAGS` or `cfg` attr's,
/// or directly into the workspace `Cargo.toml` for `styx` etc.
///
/// NOTE: The default tracing plugin, [`ProcessorTracingPlugin`], MUST
/// be enabled in order for other trace plugins to function.

#[cfg(any(tracy, doc))]
#[derive(Debug, Default)]
pub struct TracyProfilerPlugin;

#[cfg(any(tracy, doc))]
impl Plugin for TracyProfilerPlugin {
    fn name(&self) -> &str {
        "Tracy Profiler"
    }
}

#[cfg(any(tracy, doc))]
impl UninitPlugin for TracyProfilerPlugin {
    fn init(
        self: Box<Self>,
        _proc: &mut BuildingProcessor,
    ) -> Result<Box<dyn Plugin>, UnknownError> {
        TRACING_LAYERS.push(Box::new(tracing_tracy::TracyLayer::default()));
        Ok(self)
    }
}

#[cfg(any(tracy, doc))]
styx_uconf::register_component!(register plugin: id = tracy_profiler, component = TracyProfilerPlugin);
