.. _custom_backends:

Custom Execution Backends
#########################

Styx allows you to implement custom CPU backends for specialized emulation needs, such as symbolic execution, custom instrumentation, integration with external emulators, or hardware-in-the-loop testing.

Overview
========

A custom backend replaces the default execution engines (Unicorn or Pcode) with your own implementation. This enables:

* **Custom Implementation** - Something not supported how you need in the in-tree backends? Fix it
* **Custom Architecture Support** - Missing support for an architecture you need? Make it
* **Custom Instrumentation** - Fine-grained control over instruction semantics
* **Hardware Integration** - Bridge to physical hardware or FPGA implementations
* **Specialized Analysis** - Taint tracking, data flow analysis, or custom metrics
* **External Emulators** - Wrap existing emulation frameworks

Core Traits
===========

To create a custom backend, implement two core traits:

CpuBackend Trait
----------------

The ``CpuBackend`` trait defines the execution engine interface:

.. code-block:: rust

    use styx_emulator::prelude::*;

    impl CpuBackend for MyBackend {
        fn execute(
            &mut self,
            mmu: &mut Mmu,
            event_controller: &mut EventController,
            count: u64,
        ) -> Result<ExecutionReport, UnknownError> {
            // Your execution logic here
            // Return appropriate ExecutionReport variant
        }

        fn read_register_raw(&mut self, reg: ArchRegister)
            -> Result<RegisterValue, ReadRegisterError> {
            // Implement register reads
        }

        fn write_register_raw(
            &mut self,
            reg: ArchRegister,
            value: RegisterValue
        ) -> Result<(), WriteRegisterError> {
            // Implement register writes
        }

        fn pc(&mut self) -> Result<u64, UnknownError> {
            // Return current program counter
        }

        fn set_pc(&mut self, value: u64) -> Result<(), UnknownError> {
            // Set program counter
        }

        fn stop(&mut self) {
            // Stop execution
        }

        fn context_save(&mut self) -> Result<(), UnknownError> {
            // Save execution context
        }

        fn context_restore(&mut self) -> Result<(), UnknownError> {
            // Restore execution context
        }

        fn architecture(&self) -> &dyn ArchitectureDef {
            // Return architecture definition
        }

        fn endian(&self) -> ArchEndian {
            // Return endianness
        }
    }

Hookable Trait
--------------

The ``Hookable`` trait enables hook support:

.. code-block:: rust

    impl Hookable for MyBackend {
        fn add_hook(&mut self, hook: StyxHook)
            -> Result<HookToken, AddHookError> {
            // Store and manage hooks
            // Return unique token for later removal
        }

        fn delete_hook(&mut self, token: HookToken)
            -> Result<(), DeleteHookError> {
            // Remove hook by token
        }
    }

Implementation Ideas
====================

The following sections provide **pseudocode examples** to illustrate potential custom backend implementations. These are conceptual examples meant to inspire your own implementations, not working code.

Basic Custom Backend (Conceptual Example)
------------------------------------------

A minimal implementation that counts instructions:

.. code-block:: rust

    // PSEUDOCODE - Conceptual example
    #[derive(Debug)]
    struct InstructionCounterBackend {
        total_instructions: u64,
        registers: HashMap<ArchRegister, u64>,
        pc: u64,
        running: bool,
    }

    impl CpuBackend for InstructionCounterBackend {
        fn execute(
            &mut self,
            mmu: &mut Mmu,
            event_controller: &mut EventController,
            count: u64,
        ) -> Result<ExecutionReport, UnknownError> {
            let mut executed = 0;

            while executed < count && self.running {
                // Pseudocode: Fetch instruction
                let insn_bytes = mmu.read_bytes(self.pc, 4)?;

                // Pseudocode: Decode (simplified)
                let insn_size = decode_instruction(&insn_bytes)?;

                // Execute (custom logic here)
                self.total_instructions += 1;
                executed += 1;

                // Advance PC
                self.pc += insn_size as u64;

                // Check for interrupts
                if event_controller.has_pending_interrupt() {
                    return Ok(ExecutionReport::Interrupt(
                        event_controller.get_interrupt()?
                    ));
                }
            }

            Ok(ExecutionReport::instructions_complete(executed))
        }

        // ... other trait methods
    }

Symbolic Execution Backend (Conceptual Example)
------------------------------------------------

**Pseudocode** showing how you might track symbolic values through execution:

.. code-block:: rust

    // PSEUDOCODE - This is a conceptual example to illustrate the idea
    #[derive(Debug)]
    struct SymbolicBackend {
        concrete_state: ConcreteState,
        symbolic_state: SymbolicState,
        path_constraints: Vec<Constraint>,
        solver: Z3Solver,
    }

    impl CpuBackend for SymbolicBackend {
        fn execute(
            &mut self,
            mmu: &mut Mmu,
            event_controller: &mut EventController,
            count: u64,
        ) -> Result<ExecutionReport, UnknownError> {
            // Pseudocode showing symbolic execution concepts
            for _ in 0..count {
                let insn = self.fetch_decode(mmu)?;

                match insn {
                    Instruction::Branch(condition, target) => {
                        // Evaluate symbolically
                        let sym_cond = self.evaluate_condition(condition)?;

                        if sym_cond.is_symbolic() {
                            // Fork execution paths (conceptual)
                            self.fork_path(sym_cond, target)?;
                        } else {
                            // Concrete execution
                            if sym_cond.is_true() {
                                self.concrete_state.pc = target;
                            }
                        }
                    },
                    Instruction::Load(dest, addr) => {
                        // Check if address is symbolic
                        let sym_addr = self.symbolic_state.get_address(addr)?;
                        if sym_addr.is_symbolic() {
                            // Create symbolic value (conceptual)
                            let sym_val = self.create_symbolic_value();
                            self.symbolic_state.set_register(dest, sym_val);
                        } else {
                            // Concrete load
                            let value = mmu.read_u32(sym_addr.concrete())?;
                            self.concrete_state.set_register(dest, value);
                        }
                    },
                    // ... handle other instructions
                }
            }

            Ok(ExecutionReport::instructions_complete(count))
        }

        // ... other methods
    }

Hardware-in-the-Loop Backend (Conceptual Example)
--------------------------------------------------

**Pseudocode** illustrating how you might bridge to actual hardware:

.. code-block:: rust

    // PSEUDOCODE - Conceptual example for hardware integration
    struct HardwareBackend {
        jtag_interface: JtagInterface,  // Hypothetical JTAG library
        cache: RegisterCache,
    }

    impl CpuBackend for HardwareBackend {
        fn execute(
            &mut self,
            mmu: &mut Mmu,
            event_controller: &mut EventController,
            count: u64,
        ) -> Result<ExecutionReport, UnknownError> {
            // Pseudocode for hardware control
            // Configure hardware breakpoint after N instructions
            self.jtag_interface.set_instruction_breakpoint(count)?;

            // Resume hardware execution
            self.jtag_interface.resume()?;

            // Wait for breakpoint or interrupt
            let status = self.jtag_interface.wait_for_halt()?;

            match status {
                HaltReason::Breakpoint => {
                    Ok(ExecutionReport::instructions_complete(count))
                },
                HaltReason::Exception(num) => {
                    Ok(ExecutionReport::Exception(num))
                },
                // ... other cases
            }
        }

        fn read_register_raw(&mut self, reg: ArchRegister)
            -> Result<RegisterValue, ReadRegisterError> {
            // Pseudocode: Read from hardware via JTAG
            let value = self.jtag_interface.read_register(reg)?;
            self.cache.update(reg, value);
            Ok(value.into())
        }

        // ... other methods
    }

Working Example
===============

For a minimal working example, see ``examples/external-backend/src/main.rs`` in the Styx repository:

.. code-block:: rust

    // From examples/external-backend/src/main.rs
    #[derive(Debug)]
    struct CustomBackend {}

    impl CpuBackend for CustomBackend {
        fn execute(
            &mut self,
            _mmu: &mut Mmu,
            _event_controller: &mut EventController,
            count: u64,
        ) -> Result<ExecutionReport, UnknownError> {
            println!("executing {count} instructions");
            Ok(ExecutionReport::instructions_complete(count))
        }

        // ... implement other required methods
    }

Also see the ``styx-cpu-unicorn-backend`` and ``styx-cpu-pcode-backend`` for real world usages.

Integration with ProcessorBuilder
==================================

Using a Custom Backend
----------------------

Integrate your backend with the processor builder:

.. code-block:: rust

    use styx_emulator::prelude::*;

    let proc = ProcessorBuilder::default()
        .with_builder(|args: &BuildProcessorImplArgs| {
            // Create your custom backend
            let cpu = Box::new(MyCustomBackend::new());

            Ok(ProcessorBundle {
                cpu,
                ..Default::default()
            })
        })
        .with_target_program("firmware.bin")
        .build()?;

Testing Your Backend
====================

Test your backend implementation:

.. code-block:: rust

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_basic_execution() {
            let mut backend = MyBackend::new();
            let mut mmu = Mmu::default();
            let mut event_controller = DummyEventController;

            // Set up test conditions
            backend.set_pc(0x1000)?;

            // Execute
            let report = backend.execute(&mut mmu, &mut event_controller, 4)?;

            // Verify behavior
            assert_eq!(report, ExecutionReport::instructions_complete(4));
        }
    }

If you would like to assert conformance on architectures shared with other backends, you
can use the ``comparison_tests.rs`` test suite as a guide. For simple benchmarking something like
``benches/pcode_vs_unicorn_ppc.rs`` is a good starting point.

See Also
========

* :ref:`hooks` - Hook system for extending behavior
* :ref:`plugins` - Plugin development guide
* :ref:`processors` - Processor implementation
* ``examples/external-backend/`` - Minimal working example
