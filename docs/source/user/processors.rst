.. _processors:

Working with Processors
#######################

A ``Processor`` is the main computational unit in Styx that emulates a target system. It combines CPU emulation, memory management, event handling, and plugin support into a cohesive execution environment.

Architecture Overview
=====================

The processor architecture in Styx follows a builder pattern with these key components:

* **ProcessorBuilder** - Assembles all components into a working processor
* **ProcessorImpl** - Trait for custom processor implementations
* **ProcessorCore** - Contains CPU backend, MMU, and event controller
* **Executor** - Orchestrates program execution with constraints
* **Plugins** - Extend processor functionality (debugging, tracing, etc.)

Creating a Processor
====================

Basic Usage
-----------

The simplest way to create a processor is using the ``ProcessorBuilder``:

.. code-block:: rust

    use styx_processor::processor::{ProcessorBuilder, Processor};
    use styx_processor::core::builder::DummyProcessorBuilder;
    use styx_cpu_type::Backend;

    let mut proc: Processor = ProcessorBuilder::default()
        .with_builder(DummyProcessorBuilder)
        .with_backend(Backend::Unicorn)
        .with_target_program("firmware.bin")
        .build()?;

    // Run for 1000 instructions
    proc.run(1000)?;

Using Pre-built Processors
---------------------------

Styx provides several pre-built processor implementations:

.. code-block:: rust

    use styx_emulator::processors::arm::stm32f107::Stm32f107Builder;

    let mut proc = ProcessorBuilder::default()
        .with_builder(Stm32f107Builder::default())
        .with_target_program("stm32_firmware.bin")
        .with_backend(Backend::Unicorn)
        .build()?;

Raw Processor for quick development
---------------------------------------

For quick or developing custom configurations, use ``RawProcessor``, this is
essentially equivalent to using something like the ``unicorn-engine``:

.. code-block:: rust

    use styx_emulator::processors::RawProcessor;
    use styx_emulator::prelude::*;

    let mut proc = ProcessorBuilder::default()
        .with_builder(RawProcessor::new(
            Arch::SuperH,
            SuperHVariants::SH2A,
            ArchEndian::BigEndian,
        ))
        .with_loader(ParameterizedLoader)
        .with_target_program("load.yaml")
        .build()?;

See :ref:`unicorn_replacement` for more.

Implementing Custom Processors
==============================

The ProcessorImpl Trait
-----------------------

To create a custom processor, implement the ``ProcessorImpl`` trait (the ``Peripheral`` types
here are pseudo types to illustrate the point, see the codebase for examples):

.. code-block:: rust

    use styx_processor::core::builder::{ProcessorImpl, ProcessorBundle};

    pub struct MyCustomProcessor {
        pub exception_behavior: ExceptionBehavior,
    }

    impl ProcessorImpl for MyCustomProcessor {
        fn build(&self, args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError> {
            // Create CPU backend based on selected backend type
            let cpu: Box<dyn CpuBackend> = match args.backend {
                Backend::Pcode => Box::new(PcodeBackend::new_engine_config(
                    MyArchVariant,
                    ArchEndian::LittleEndian,
                    &args.into(),
                )),
                Backend::Unicorn => Box::new(UnicornBackend::new_engine_exception(
                    Arch::MyArch,
                    MyArchVariant,
                    ArchEndian::LittleEndian,
                    args.exception,
                )),
            };

            // Setup memory management unit
            let mut mmu = Mmu::default_region_store();
            setup_address_space(&mut mmu)?;

            // Create event controller (interrupt controller)
            let event_controller = Box::new(MyEventController::default());

            // Add peripherals
            let mut peripherals: Vec<Box<dyn Peripheral>> = Vec::new();
            peripherals.push(Box::new(UartPeripheral::new()));
            peripherals.push(Box::new(GpioPeripheral::new()));

            // Provide loader hints
            let mut loader_hints = LoaderHints::new();
            loader_hints.insert("arch".into(), Box::new(Arch::MyArch));

            Ok(ProcessorBundle {
                cpu,
                mmu,
                event_controller,
                peripherals,
                loader_hints,
            })
        }

        fn init(&self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
            // Initialize processor state after building
            populate_default_registers(proc.core.cpu.as_mut())?;
            Ok(())
        }
    }

Key Components
==============

ProcessorBundle
---------------

The ``ProcessorBundle`` contains all uninitialized components:

* **cpu**: CPU backend (Unicorn or Pcode)
* **mmu**: Memory management unit with address space configuration
* **event_controller**: Handles interrupts and exceptions
* **peripherals**: List of peripheral devices
* **loader_hints**: Hints for the program loader

Memory Configuration
--------------------

Configure the address space by adding memory regions:

.. code-block:: rust

    fn setup_address_space(mmu: &mut Mmu) -> Result<(), UnknownError> {
        let mut regions = Vec::new();

        // Add RAM
        regions.push(MemoryRegion::new(
            0x2000_0000,  // start address
            96 * 1024,    // size
            MemoryPermissions::all()
        )?);

        // Add Flash with initial data
        regions.push(MemoryRegion::new_with_data(
            0x0800_0000,
            0x10_0000,
            MemoryPermissions::all(),
            vec![0xFF; 0x10_0000]
        )?);

        // Create memory alias
        let flash = MemoryRegion::new(0x0800_0000, 0x10_0000, MemoryPermissions::all())?;
        let alias = flash.new_alias(0x0000_0000);
        regions.push(flash);
        regions.push(alias);

        mmu.add_memory_regions(regions)?;
        Ok(())
    }

Execution Control
=================

The processor supports various execution modes:

.. code-block:: rust

    // Run for specific instruction count
    proc.run(1000)?;

    // Run for duration
    proc.run(Duration::from_millis(100))?;

    // Run forever (until stopped by hook)
    proc.run(Forever)?;

    // the above is also equivalent `.start()`
    proc.start()?;

Extending Processor Behavior
=============================

Styx provides multiple mechanisms for extending and customizing processor behavior:

Hooks
-----

Hooks allow you to intercept and modify execution at specific points. Common uses include:

* Monitoring function calls and returns
* Implementing MMIO peripherals
* Injecting faults for testing

Basic hook example:

.. code-block:: rust

    ProcessorBuilder::default()
        .add_hook(StyxHook::code(0x1000, |proc| {
            println!("Function at 0x1000 called");
            Ok(())
        }))
        .add_hook(StyxHook::memory_write(0x4000_0000..=0x4000_FFFF, |proc, addr, size, value| {
            println!("MMIO write: 0x{:x} = 0x{:x}", addr, value);
            Ok(())
        }))
        .build()?;

For comprehensive hook documentation, see :ref:`hooks`.

Plugins
-------

Plugins provide lifecycle management and can install multiple hooks:

.. code-block:: rust

    ProcessorBuilder::default()
        .add_plugin(ProcessorTracingPlugin)
        .add_plugin(GdbPlugin::new(GdbPluginParams::new("0.0.0.0", 3333, true))
        .add_plugin(UnmappedMemoryFaultPlugin::new(true))
        .build()?;

For plugin development guide, see :ref:`plugins`.

Custom Backends
---------------

For specialized emulation needs, you can implement custom execution backends:

.. code-block:: rust

    ProcessorBuilder::default()
        .with_builder(|args| {
            let cpu = Box::new(MyCustomBackend::new());
            Ok(ProcessorBundle { cpu, ..Default::default() })
        })
        .build()?;

For custom backend implementation, see :ref:`custom_backends`.

Thread Safety
=============

* ``Processor`` implements ``Send`` but not ``Sync``
* For concurrent access, use ``SyncProcessor`` wrapper
* Multiple processors can run in parallel on different threads

Examples
========

See the examples in ``examples/`` directory for small isolated working implementations,
see the ``processors/`` for real world examples.
