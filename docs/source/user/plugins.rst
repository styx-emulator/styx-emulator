.. _plugins:

Building Custom Plugins
#######################

Plugins extend processor functionality and can modify behavior throughout the emulation lifecycle. They provide a clean way to add features like debugging, tracing, coverage analysis, fuzzing, and custom instrumentation.

Overview
========

Plugins in Styx operate in two phases:

1. **Initialization Phase** (``UninitPlugin``) - Configure the processor before execution starts
2. **Runtime Phase** (``Plugin``) - Interact with the processor during execution

Plugins can:

* Install hooks to intercept execution
* Modify memory mappings and permissions
* Modify runtime behavior
* Collect metrics and traces
* Integrate with external tools

Core Traits
===========

UninitPlugin Trait
------------------

The initialization interface for plugins:

.. code-block:: rust

    use styx_emulator::prelude::*;

    impl UninitPlugin for MyPlugin {
        fn init(
            self: Box<Self>,
            proc: &mut BuildingProcessor,
        ) -> Result<Box<dyn Plugin>, UnknownError> {
            // Access to processor components during building
            // - proc.core.cpu: Install hooks
            // - proc.core.mmu: Configure memory
            // - proc.core.event_controller: Set up interrupts

            // Return self as Plugin for runtime phase
            Ok(self)
        }
    }

Plugin Trait
------------

The runtime interface for plugins:

.. code-block:: rust

    impl Plugin for MyPlugin {
        fn name(&self) -> &str {
            "MyPlugin"
        }

        // Optional lifecycle callbacks
        fn on_start(&mut self, proc: &mut Processor) -> Result<(), UnknownError> {
            // Called when emulation starts
            Ok(())
        }

        fn on_stop(&mut self, proc: &mut Processor) -> Result<(), UnknownError> {
            // Called when emulation stops
            Ok(())
        }
    }

Basic Plugin Examples
=====================

Simple Tracing Plugin
---------------------

A plugin that logs all executed instructions:

.. code-block:: rust

    use styx_emulator::prelude::*;
    use tracing::info;

    pub struct InstructionTracer {
        instruction_count: u64,
    }

    impl UninitPlugin for InstructionTracer {
        fn init(
            mut self: Box<Self>,
            proc: &mut BuildingProcessor,
        ) -> Result<Box<dyn Plugin>, UnknownError> {
            // Install a code hook that triggers on every instruction
            proc.core.cpu.add_hook(StyxHook::code(
                ..,  // Unbounded range - triggers on all addresses
                move |proc: CoreHandle| {
                    let pc = proc.pc()?;
                    info!("Executing instruction at 0x{:x}", pc);
                    Ok(())
                }
            ))?;

            Ok(self)
        }
    }

    impl Plugin for InstructionTracer {
        fn name(&self) -> &str {
            "InstructionTracer"
        }
    }

Memory Fault Detector
---------------------

A plugin that catches and reports memory access violations:

.. code-block:: rust

    pub struct MemoryFaultDetector {
        halt_on_fault: bool,
        fault_count: u32,
    }

    impl UninitPlugin for MemoryFaultDetector {
        fn init(
            mut self: Box<Self>,
            proc: &mut BuildingProcessor,
        ) -> Result<Box<dyn Plugin>, UnknownError> {
            let halt = self.halt_on_fault;

            // Install unmapped memory fault hook
            proc.core.cpu.add_hook(StyxHook::UnmappedFault(
                (..).into(),
                Box::new(move |proc: CoreHandle, addr: u64, size: u32, data| {
                    error!("Unmapped memory access at 0x{:x}, size {}", addr, size);
                    if halt {
                        proc.cpu.stop();
                    }
                    Ok(Resolution::NotFixed)
                })
            ))?;

            Ok(self)
        }
    }

    impl Plugin for MemoryFaultDetector {
        fn name(&self) -> &str {
            "MemoryFaultDetector"
        }
    }

Stateful Plugin with Hooks
---------------------------

Showing a plugin that maintains state across hook calls:

.. code-block:: rust

    // PSEUDOCODE - Illustrative example
    use std::sync::{Arc, Mutex};

    pub struct CoveragePlugin {
        // Shared state between plugin and hooks
        executed_blocks: Arc<Mutex<HashSet<u64>>>,
        output_path: PathBuf,
    }

    impl UninitPlugin for CoveragePlugin {
        fn init(
            mut self: Box<Self>,
            proc: &mut BuildingProcessor,
        ) -> Result<Box<dyn Plugin>, UnknownError> {
            // Clone Arc for the hook closure
            let coverage = self.executed_blocks.clone();

            // Install block hook to track coverage
            proc.core.cpu.add_hook(StyxHook::block(
                ..,
                move |proc: CoreHandle, addr: u64, size: u32| {
                    coverage.lock().unwrap().insert(addr);
                    Ok(())
                }
            ))?;

            Ok(self)
        }
    }

    impl Plugin for CoveragePlugin {
        fn name(&self) -> &str {
            "Coverage"
        }

        fn on_stop(&mut self, _proc: &mut Processor) -> Result<(), UnknownError> {
            // Write coverage report when emulation stops
            let blocks = self.executed_blocks.lock().unwrap();
            let report = format!("Covered {} unique blocks", blocks.len());
            std::fs::write(&self.output_path, report)?;
            Ok(())
        }
    }

Plugin Communication
====================

Plugins can communicate with external systems:

.. code-block:: rust

    pub struct NetworkMonitorPlugin {
        server: TcpListener,
    }

    impl Plugin for NetworkMonitorPlugin {
        fn name(&self) -> &str {
            "NetworkMonitor"
        }

        fn on_start(&mut self, proc: &mut Processor) -> Result<(), UnknownError> {
            // Start network server in background
            let server = self.server.try_clone()?;
            std::thread::spawn(move || {
                for stream in server.incoming() {
                    // Handle monitoring connections
                }
            });
            Ok(())
        }
    }

Using Plugins
=============

Adding Plugins to a Processor
------------------------------

.. code-block:: rust

    use styx_emulator::prelude::*;

    let mut proc = ProcessorBuilder::default()
        .with_builder(MyProcessorBuilder)
        // Add multiple plugins
        .add_plugin(InstructionTracer::new())
        .add_plugin(MemoryFaultDetector::new(true))
        .add_plugin(CoveragePlugin::new("coverage.txt"))
        .add_plugin(ProcessorTracingPlugin)
        .build()?;

Performance Considerations
==========================

**Hook Overhead**: Every hook adds overhead, please treat the ``Hook``/``Plugin`` dichotomy
like the top/bottom half interrupt processing ("top-half" responds to the interrupt, puts stuff
on a queue etc. to be handled by the "bottom-half" later). In this case the hook is the top-half
that would put data on a queue or channel for the plugin to handle in an async service it spawns
in the tokio runtime assigned to the ``Processor``.

See Also
========

* :ref:`hooks` - Hook system documentation
* :ref:`processors` - Processor implementation
* :ref:`custom_backends` - Custom execution backends
* ``examples/fuzzer-plugin/`` - Complete fuzzing plugin example
* ``styx/plugins/`` - Source code for built-in plugins
