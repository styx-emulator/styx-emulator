// SPDX-License-Identifier: BSD-2-Clause
//! `ProcessorBuilder` logic and utilities
use std::borrow::Cow;

use log::{debug, info};
use styx_cpu_type::Backend;
use styx_errors::{anyhow::Context, UnknownError};
use styx_loader::{Loader, LoaderHints, RawLoader};
use tokio::{net::TcpListener, runtime::Handle};
use tonic::{service::RoutesBuilder, transport::Server};

use crate::{
    core::{
        builder::{
            BuildProcessorImplArgs, ProcessorBundle, ProcessorImpl, UnimplementedProcessorImpl,
        },
        ExceptionBehavior, ProcMeta, ProcessorCore,
    },
    cpu::CpuBackendExt,
    event_controller::EventController,
    executor::{DefaultExecutor, Executor, ExecutorImpl},
    hooks::StyxHook,
    plugins::{collection::PluginsContainer, UninitPlugin},
    runtime::ProcessorRuntime,
};

use super::{Processor, SyncProcessor};

/// A private wrapper type to mark the source of a `TargetProgram`
#[derive(Debug)]
enum TargetProgramSource<'a> {
    /// From a file at this path.
    File(String),
    /// From in-memory bytes
    Memory(Cow<'a, [u8]>),
}

impl<'a> TargetProgramSource<'a> {
    pub fn bytes(self) -> Result<Cow<'a, [u8]>, std::io::Error> {
        match self {
            TargetProgramSource::File(file_name) => std::fs::read(file_name).map(Cow::Owned),
            TargetProgramSource::Memory(cow) => Ok(cow),
        }
    }
}

/// The central point to create a new [`Processor`].
///
/// The target program is a set of bytes for the target to load at build time. It can be passed as a
/// byte slice via [`ProcessorBuilder::with_input_bytes()`] or by file name with
/// [`ProcessorBuilder::with_target_program()`]. These are loaded by the loader which is set by
/// default to the [`RawLoader`] which loads the target program at address 0. Other loaders are
/// available in [`styx_loader`].
///
/// See the documentation for [`Self::build()`] for more information.
///
/// # Example
///
/// ```
/// # use styx_processor::executor::DefaultExecutor;
/// # use styx_processor::processor::{ProcessorBuilder, Processor};
/// # use styx_processor::core::builder::DummyProcessorBuilder;
/// # use styx_cpu_type::Backend;
/// # use std::time::Duration;
/// // process is owned and must be mutable.
/// let proc: Processor = ProcessorBuilder::default()
///     .with_executor(DefaultExecutor)
///     .with_backend(Backend::Unicorn)
///     .with_builder(DummyProcessorBuilder)
///     .build().unwrap();
///
/// ```
pub struct ProcessorBuilder<'a> {
    executor: Box<dyn ExecutorImpl>,
    runtime: ProcessorRuntime,
    plugins: PluginsContainer<Box<dyn UninitPlugin>>,
    port: IPCPort,
    builder: Box<dyn ProcessorImpl>,
    target_program_source: Option<TargetProgramSource<'a>>,
    loader: Box<dyn Loader>,
    cpu_backend: Backend,
    exception_behavior: ExceptionBehavior,
    hooks: Vec<StyxHook>,
}
impl<'a> Default for ProcessorBuilder<'a> {
    fn default() -> Self {
        Self {
            executor: Box::new(DefaultExecutor),
            runtime: ProcessorRuntime::default(),
            plugins: PluginsContainer::default(),
            port: IPCPort::default(),
            builder: Box::new(UnimplementedProcessorImpl),
            target_program_source: None,
            loader: Box::new(RawLoader),
            cpu_backend: Backend::default(),
            exception_behavior: ExceptionBehavior::default(),
            hooks: Vec::new(),
        }
    }
}

impl<'a> ProcessorBuilder<'a> {
    /// Specify the target program using a path to a target program to be loaded.
    ///
    /// This will override any previous calls to [Self::with_input_bytes()] or
    /// [Self::with_target_program()].
    pub fn with_target_program(mut self, target_program_path: impl Into<String>) -> Self {
        self.target_program_source = Some(TargetProgramSource::File(target_program_path.into()));
        self
    }

    /// Specify the target program using a byte array, owned or borrowed.
    ///
    /// This will override any previous calls to [Self::with_input_bytes()] or
    /// [Self::with_target_program()].
    pub fn with_input_bytes(mut self, input_bytes: Cow<'a, [u8]>) -> Self {
        self.target_program_source = Some(TargetProgramSource::Memory(input_bytes));
        self
    }

    /// Specifies the [`Loader`] to use for the `TargetProgram`.
    ///
    /// This type must be resolvable at compile-time.
    pub fn with_loader(mut self, loader: impl Loader + 'static) -> Self {
        self.loader = Box::new(loader);
        self
    }
    pub fn with_loader_box(mut self, loader: Box<dyn Loader + 'static>) -> Self {
        self.loader = loader;
        self
    }

    /// Specifies the [`Backend`] to use for instruction emulation.
    ///
    /// If this is not provided, [`Backend::default()`] is selected.
    pub fn with_backend(mut self, cpu_backend: Backend) -> Self {
        self.cpu_backend = cpu_backend;
        self
    }

    /// Specifies the [`ExecutorImpl`] to use for this [`Processor`].
    ///
    /// This defaults to [`DefaultExecutor`], which is a sane default unless
    /// you want to do something specific (like fuzzing, debugging or something
    /// that is dependent on state outside of Styx-proper).
    pub fn with_executor(mut self, executor: impl ExecutorImpl + 'static) -> Self {
        self.executor = Box::new(executor);
        self
    }

    /// Specifies the [`ExecutorImpl`] to use for this [`Processor`].
    ///
    /// This method is the same as [`Self::with_executor()`] with the
    /// benefit of being able to consume an executor already
    /// wrapped in a [`Box`].
    pub fn with_executor_box(mut self, executor: Box<dyn ExecutorImpl + 'static>) -> Self {
        self.executor = executor;
        self
    }

    /// Specifies the [`IPCPort`] to use for all I/O and peripherals.
    ///
    /// Note that [`Plugin`](crate::plugins::Plugin)'s can technically start their own anything,
    /// but should play nice when possible by adding a service to the peripherals'
    /// gRPC server that *always* exists.
    pub fn with_ipc_port(mut self, ipc_port: impl Into<IPCPort>) -> Self {
        self.port = ipc_port.into();
        self
    }

    pub fn with_exception_behavior(mut self, exception_behavior: ExceptionBehavior) -> Self {
        self.exception_behavior = exception_behavior;
        self
    }

    /// Specifies the [`ProcessorImpl`] builder method to use.
    ///
    /// While this technically reduces a "Processor" to a couple functions,
    /// this allows for an extremely FFI friendly API and is nicer overall
    /// than relying on a more typed-out interface.
    ///
    /// This is a **required** argument the the [`ProcessorBuilder`] and
    /// is used to initialize the available configuration, and then to initialize
    /// the runtime behavior via various hooks. See the [`ProcessorImpl`]
    /// documentation for more information.
    pub fn with_builder(mut self, builder: impl ProcessorImpl + 'static) -> Self {
        self.builder = Box::new(builder);
        self
    }

    /// Specifies an [`UninitPlugin`] to add to the [`Processor`] instance.
    ///
    /// It is currently on the user to ensure any [`Plugin`](crate::plugins::Plugin) dependencies are
    /// resolved / managed, and that none are conflicting. Please reach out to
    /// the developers if you have strong opinions on any future dependency
    /// resolution behavior.
    pub fn add_plugin(mut self, plugin: impl UninitPlugin + 'static) -> Self {
        self.plugins.plugins.push(Box::new(plugin));
        self
    }

    /// Specifies an [`UninitPlugin`] to add to the [`Processor`] instance.
    ///
    /// This method is the same as [`Self::add_plugin()`] save for
    /// being able to consume a [`UninitPlugin`] already in a [`Box`].
    pub fn add_plugin_box(mut self, plugin: Box<dyn UninitPlugin + 'static>) -> Self {
        self.plugins.plugins.push(plugin);
        self
    }

    /// Specifies any amount of [`StyxHook`]'s to add to the eventual
    /// [`Processor`] instance.
    ///
    /// It is not required to add hooks at build/compile time. And you can
    /// add/remove hooks while inside another hook! See the documentation
    /// for [`StyxHook`] for more information.
    pub fn add_hook(mut self, hook: StyxHook) -> Self {
        self.hooks.push(hook);
        self
    }

    /// Builds the processor and initializes it.
    ///
    /// Required components:
    /// - [`ProcessorImpl`] via [`Self::with_builder()`]
    /// - A `TargetProgram` stored as [`TargetProgramSource`] via
    ///   [`Self::with_input_bytes()`] or [`Self::with_target_program`].
    ///   - **NOTE**: If the loader is [`ParameterizedLoader`](styx_loader::ParameterizedLoader) then things
    ///     get a little more complicated, see the documentation for
    ///     [`ParameterizedLoader`](styx_loader::ParameterizedLoader) for more information.
    ///
    /// Once this method returns you'll have a [`Processor`] ready to run code!
    ///
    // **NOTE**: The bulk of the work happens in [ProcessorBuilder::build_inner()].
    pub fn build(mut self) -> Result<Processor, UnknownError> {
        let builder = std::mem::replace(&mut self.builder, Box::new(UnimplementedProcessorImpl));
        let args = BuildProcessorImplArgs {
            runtime: self.runtime.handle(),
            backend: self.cpu_backend,
            exception: self.exception_behavior,
        };
        let processor = builder.build(&args)?;
        self.build_inner(processor, builder)
    }

    pub fn build_sync(self) -> Result<SyncProcessor, UnknownError> {
        SyncProcessor::from_builder(self)
    }

    /// Builds processor and initializes components.
    fn build_inner(
        self,
        bundle: ProcessorBundle,
        builder: Box<dyn ProcessorImpl>,
    ) -> Result<Processor, UnknownError> {
        let mut runtime = self.runtime;

        let mut cpu = bundle.cpu;
        let mut mmu = bundle.mmu;

        let mut event_controller_impl = bundle.event_controller;
        event_controller_impl.init(cpu.as_mut(), &mut mmu)?;
        let event_controller = EventController::new(event_controller_impl);

        let mut core = ProcessorCore {
            cpu,
            mmu,
            event_controller,
        };

        autobots_load_up(
            self.loader,
            bundle.loader_hints,
            self.target_program_source,
            &mut core,
        )?;

        let executor = Executor::new(self.executor);

        let mut peripherals = bundle.peripherals;

        for hook in self.hooks {
            core.cpu
                .add_hook(hook)
                .context("failed to add initial processor hooks")?;
        }

        let mut building_processor = BuildingProcessor::new(&mut core, &mut runtime);

        debug!("initializing plugins");
        let mut plugins = self
            .plugins
            .init_all(&mut building_processor)
            .context("failed initializing plugins")?;
        plugins
            .post_init_all(&mut building_processor)
            .context("failed post init plugins")?;

        debug!("initializing processor");
        builder.init(&mut building_processor)?;

        // initialize peripherals
        debug!("initializing peripherals");
        for peripheral in peripherals.iter_mut() {
            debug!("initializing peripheral {}", peripheral.name());
            peripheral.init(&mut building_processor)?;
            peripheral.reset(
                building_processor.core.cpu.as_mut(),
                &mut building_processor.core.mmu,
            )?;
        }

        let port = start_ipc(building_processor.routes, runtime.handle(), self.port)?;

        // transfer ownership of peripherals to event controller
        for peripheral in peripherals {
            core.event_controller.add_peripheral(peripheral)?;
        }

        // initialize plugins, runtime, executor, etc.
        let system = Processor {
            executor,
            runtime,
            core,
            meta: ProcMeta {},
            plugins,
            port,
        };

        Ok(system)
    }
}

/// applies loader to core state
fn autobots_load_up(
    loader: Box<dyn Loader>,
    hints: LoaderHints,
    source: Option<TargetProgramSource>,
    core: &mut ProcessorCore,
) -> Result<(), UnknownError> {
    debug!("autobots_load_up loader: {loader:?} source: {source:?}");

    let Some(source) = source else {
        // no source, we don't have to do anything
        return Ok(());
    };

    let source_bytes = source.bytes()?;

    // loader hints?
    let mut memory_desc = loader
        .load_bytes(source_bytes, hints)
        .context("failed to let loader load bytes")?;

    // todo these should be more compatible
    let regions = memory_desc.take_memory_regions();
    debug!("got {} regions from loader", regions.len());
    for region in regions.into_iter() {
        debug!("loading region {region:X?}");
        let region_data = region.read_data(region.base(), region.size()).unwrap();
        core.mmu.write_code(region.base(), &region_data)?;
    }

    for (register, value) in memory_desc.take_registers().into_iter() {
        // mildly sketchy but should mostly work out ok wrt converting
        match TryInto::<u32>::try_into(value) {
            Ok(value_u32) => core.cpu.write_register(register, value_u32)?,
            Err(_) => core.cpu.write_register(register, value)?,
        }
    }

    Ok(())
}

pub struct BuildingProcessor<'a> {
    pub core: &'a mut ProcessorCore,
    pub runtime: &'a mut ProcessorRuntime,
    pub routes: RoutesBuilder,
}

impl<'a> BuildingProcessor<'a> {
    pub fn new(core: &'a mut ProcessorCore, runtime: &'a mut ProcessorRuntime) -> Self {
        Self {
            core,
            runtime,
            routes: Default::default(),
        }
    }
}

/// A wrapper type for constraints surrounding port selection.
#[derive(Default, Clone, Copy)]
pub struct IPCPort(Option<u16>);

impl IPCPort {
    /// Specify to choose any available IPC port.
    pub fn any() -> Self {
        Self(None)
    }

    /// Specify to choose a specific IPC port.
    pub fn specific(port: u16) -> Self {
        Self(Some(port))
    }
}

impl From<u16> for IPCPort {
    fn from(value: u16) -> Self {
        IPCPort::specific(value)
    }
}

/// Start tonic server on async thread and returns the chosen port.
fn start_ipc(routes: RoutesBuilder, runtime: Handle, port: IPCPort) -> Result<u16, UnknownError> {
    // default to port `0`, we will let the OS choose a random port
    // and then set an internal record of the port in use
    let port = port.0.unwrap_or(0);

    // grab a tcp listener
    let tcp_listener = runtime
        .block_on(async move {
            // create the tcp listener
            TcpListener::bind(format!("0.0.0.0:{}", port)).await
        })
        .with_context(|| format!("could not bind to port {port}"))?;
    let port = tcp_listener.local_addr()?.port();

    info!("Processor IPC server listening on port {}", port);

    // spawn ipc on async runtime
    runtime.spawn(async move {
        Server::builder()
            .add_routes(routes.routes())
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(tcp_listener))
            .await
            .unwrap()
    });

    Ok(port)
}
