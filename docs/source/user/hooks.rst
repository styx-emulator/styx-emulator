.. _hooks:

Hook System
###########

Hooks are the fundamental mechanism for intercepting and modifying processor behavior in Styx. They allow peripherals, plugins, MMUs, and user code to react to processor events and influence execution.

Overview
========

The modern Styx hook API provides an ergonomic interface through the ``StyxHook`` enum, supporting:

* **Code execution** at specific addresses
* **Memory operations** (reads/writes) on address ranges
* **Register access** (reads/writes)
* **Block boundaries** for coverage tracking
* **Fault handling** for protection and unmapped memory errors
* **Interrupt events**
* **Invalid instruction** handling

The hook system is designed to be efficient and flexible, using trait-based callbacks for clean state management.

Hook Types
==========

The ``StyxHook`` enum provides all hook variants:

.. code-block:: rust

    pub enum StyxHook {
        Code(AddressRange, Box<dyn CodeHook>),
        Block(Box<dyn BlockHook>),
        MemoryRead(AddressRange, Box<dyn MemoryReadHook>),
        MemoryWrite(AddressRange, Box<dyn MemoryWriteHook>),
        ProtectionFault(AddressRange, Box<dyn ProtectionFaultHook>),
        UnmappedFault(AddressRange, Box<dyn UnmappedFaultHook>),
        Interrupt(Box<dyn InterruptHook>),
        InvalidInstruction(Box<dyn InvalidInstructionHook>),
        RegisterRead(ArchRegister, Box<dyn RegisterReadHook>),
        RegisterWrite(ArchRegister, Box<dyn RegisterWriteHook>),
    }

Code Hooks
----------

Trigger when code executes at specific addresses:

.. code-block:: rust

    use styx_processor::{StyxHook, CodeHook, CoreHandle};
    use anyhow::Error as UnknownError;

    // Implement the CodeHook trait
    struct FunctionTracer {
        call_count: usize,
    }

    impl CodeHook for FunctionTracer {
        fn code_hook(&mut self, proc: CoreHandle) -> Result<(), UnknownError> {
            self.call_count += 1;
            let pc = proc.cpu().pc()?;
            println!("Function at 0x{:x} called {} times", pc, self.call_count);
            Ok(())
        }
    }

    // Add to processor using ergonomic constructors
    let hook = StyxHook::code(0x1000..=0x1010, Box::new(FunctionTracer { call_count: 0 }));
    processor.add_hook(hook)?;

Memory Hooks
------------

Intercept memory reads and writes with full access to processor state:

.. code-block:: rust

    use styx_processor::{StyxHook, MemoryWriteHook, MemoryReadHook, CoreHandle};

    // Memory write hook
    struct UartPeripheral {
        buffer: Vec<u8>,
    }

    impl MemoryWriteHook for UartPeripheral {
        fn memory_write_hook(
            &mut self,
            proc: CoreHandle,
            address: u64,
            size: u32,
            data: &[u8],
        ) -> Result<(), UnknownError> {
            // Access CPU state
            let pc = proc.cpu().pc()?;
            println!("UART write from PC 0x{:x}: {:?}", pc, data);

            self.buffer.extend_from_slice(data);

            // Trigger interrupt when buffer is full
            if self.buffer.len() >= 16 {
                proc.event_controller().trigger_interrupt(5)?;
                self.buffer.clear();
            }

            Ok(())
        }
    }

    // Memory read hook - modify the data buffer
    struct StatusRegister {
        status: u32,
    }

    impl MemoryReadHook for StatusRegister {
        fn memory_read_hook(
            &mut self,
            proc: CoreHandle,
            address: u64,
            size: u32,
            data: &mut [u8],
        ) -> Result<(), UnknownError> {
            // Write status value to the output buffer
            let bytes = self.status.to_le_bytes();
            data[..size as usize].copy_from_slice(&bytes[..size as usize]);
            Ok(())
        }
    }

    // Register hooks with address ranges
    processor.add_hook(StyxHook::memory_write(
        0x40004800..=0x40004803,
        Box::new(UartPeripheral { buffer: Vec::new() })
    ))?;

    processor.add_hook(StyxHook::memory_read(
        0x40004804..=0x40004807,
        Box::new(StatusRegister { status: 0x00000001 })
    ))?;

Register Hooks
--------------

Monitor and modify register access:

**NOTE**: These hooks are **extremely expensive**. You probably should not ever use
these hooks outside of tinkering and debugging.

.. code-block:: rust

    use styx_processor::{StyxHook, RegisterWriteHook, RegisterReadHook};
    use styx_processor::{CoreHandle, ArchRegister, RegisterValue};

    // Monitor stack pointer changes
    struct StackMonitor {
        min_sp: u64,
        max_sp: u64,
    }

    impl RegisterWriteHook for StackMonitor {
        fn register_write_hook(
            &mut self,
            proc: CoreHandle,
            register: ArchRegister,
            data: &RegisterValue,
        ) -> Result<(), UnknownError> {
            let sp_value = data.as_u64();
            self.min_sp = self.min_sp.min(sp_value);
            self.max_sp = self.max_sp.max(sp_value);

            if sp_value < 0x20000000 {
                println!("Warning: Stack pointer below safe threshold!");
            }

            Ok(())
        }
    }

    // Modify register reads
    struct RegisterFuzzer;

    impl RegisterReadHook for RegisterFuzzer {
        fn register_read_hook(
            &mut self,
            proc: CoreHandle,
            register: ArchRegister,
            data: &mut RegisterValue,
        ) -> Result<(), UnknownError> {
            // Inject random values for testing
            *data = RegisterValue::from(rand::random::<u32>());
            Ok(())
        }
    }

Fault Hooks
-----------

Handle and potentially resolve memory faults:

.. code-block:: rust

    use styx_processor::{ProtectionFaultHook, UnmappedFaultHook, Resolution, Access};

    // Handle protection faults
    struct ProtectionHandler;

    impl ProtectionFaultHook for ProtectionHandler {
        fn protection_fault_hook(
            &mut self,
            proc: CoreHandle,
            address: u64,
            size: u32,
            access: Access,
        ) -> Result<Resolution, UnknownError> {
            println!("Protection fault at 0x{:x} ({:?})", address, access);

            // Could modify permissions here
            if address >= 0x80000000 {
                // High memory - allow access
                proc.mmu().set_permissions(address, MemoryPermissions::all())?;
                Ok(Resolution::Fixed)
            } else {
                // Low memory - deny access
                Ok(Resolution::NotFixed)
            }
        }
    }

    // Lazy memory allocation
    struct LazyAllocator;

    impl UnmappedFaultHook for LazyAllocator {
        fn unmapped_fault_hook(
            &mut self,
            proc: CoreHandle,
            address: u64,
            size: u32,
            access: Access,
        ) -> Result<Resolution, UnknownError> {
            // Allocate page on first access
            let page_start = address & !0xFFF;

            proc.mmu().add_memory_region(
                MemoryRegion::new(page_start, 0x1000, MemoryPermissions::all())
            )?;

            println!("Allocated page at 0x{:x} for {:?} access", page_start, access);
            Ok(Resolution::Fixed)
        }
    }

Block and Interrupt Hooks
-------------------------

Track basic blocks and interrupt events:

.. code-block:: rust

    use styx_processor::{BlockHook, InterruptHook};
    use std::collections::HashSet;

    // Coverage tracking
    struct CoverageTracker {
        blocks: HashSet<u64>,
    }

    impl BlockHook for CoverageTracker {
        fn block_hook(
            &mut self,
            proc: CoreHandle,
            address: u64,
            size: u32,
        ) -> Result<(), UnknownError> {
            self.blocks.insert(address);

            if self.blocks.len() % 100 == 0 {
                println!("Coverage: {} unique blocks", self.blocks.len());
            }

            Ok(())
        }
    }

    // Interrupt monitoring
    struct InterruptLogger;

    impl InterruptHook for InterruptLogger {
        fn interrupt_hook(
            &mut self,
            proc: CoreHandle,
            interrupt_num: u32,
        ) -> Result<(), UnknownError> {
            let pc = proc.cpu().pc()?;
            println!("Interrupt {} at PC 0x{:x}", interrupt_num, pc);
            Ok(())
        }
    }

CoreHandle API
==============

The ``CoreHandle`` provides safe access to processor components:

.. code-block:: rust

    // Access CPU state
    let pc = proc.cpu().pc()?;
    let sp = proc.cpu().sp()?;
    let reg_value = proc.cpu().read_register(ArchRegister::R0)?;
    proc.cpu().write_register(ArchRegister::R1, 0x1234)?;

    // Access memory through MMU
    let mut buffer = vec![0u8; 4];
    proc.mmu().read_memory(0x20000000, &mut buffer)?;
    proc.mmu().write_memory(0x20000100, &[0x42, 0x43, 0x44, 0x45])?;

    // Control execution
    proc.cpu().stop()?;
    proc.cpu().set_pc(0x08000000)?;

    // Trigger interrupts
    proc.event_controller().trigger_interrupt(23)?;

Address Range Support
=====================

Hooks support flexible Rust range syntax:

.. code-block:: rust

    // Exact single address
    StyxHook::code(0x1000, callback)

    // Inclusive range
    StyxHook::memory_write(0x1000..=0x1FFF, callback)

    // Half-open range (exclusive end)
    StyxHook::memory_write(0x1000..0x2000, callback)

    // Open-ended ranges
    StyxHook::memory_read(0x80000000.., callback)  // From address to end
    StyxHook::memory_read(..0x1000, callback)      // From start to address

    // All memory/code
    StyxHook::memory_write(.., callback)

Hook Management
===============

Dynamic Addition and Removal
----------------------------

Hooks can be added and removed at runtime:

.. code-block:: rust

    // Add hook - returns a HookToken for later removal
    let token = processor.add_hook(StyxHook::code(0x1000, callback))?;

    // Remove hook using token
    processor.remove_hook(token)?;

    // Clear all hooks
    processor.clear_hooks()?;

    // List active hooks
    for hook in processor.list_hooks() {
        println!("Active hook: {:?}", hook);
    }

.. _hook_order:

Hook Execution Order
--------------------

Hook exeecution order is strictly **unspecified**

.. code-block:: rust

    // These execute in any order regardless the order
    // they were added in
    processor.add_hook(StyxHook::code(0x1000, first_hook))?;
    processor.add_hook(StyxHook::code(0x1000, second_hook))?;
    processor.add_hook(StyxHook::code(0x1000, third_hook))?;

Performance Considerations
==========================

Best Practices
--------------

1. **Use Specific Ranges**: Exact addresses are faster than ranges
2. **Minimize Unbounded Hooks**: They trigger on every operation
3. **Add Early Returns**: Filter quickly before expensive operations
4. **Batch Operations**: Combine related operations in single hooks (eg. per peripheral)
5. **Cache Frequently Used Data**: Avoid repeated lookups

.. code-block:: rust

    // Hook with early filtering
    impl MemoryWriteHook for MyHook {
        fn memory_write_hook(
            &mut self,
            proc: CoreHandle,
            address: u64,
            size: u32,
            data: &[u8],
        ) -> Result<(), UnknownError> {
            // Quick filter - return early for uninteresting addresses
            if (address & 0xF000_0000) != 0x2000_0000 {
                return Ok(());
            }

            // Cache frequently accessed state
            if self.cache_invalid {
                self.cached_value = expensive_lookup()?;
                self.cache_invalid = false;
            }

            // Now do the actual work
            self.process_write(address, data)?;
            Ok(())
        }
    }

Other Examples
==============

Function Call Tracing
---------------------

.. code-block:: rust

    struct CallTracer {
        call_stack: Vec<(u64, String)>,
        symbols: HashMap<u64, String>,
    }

    impl CallTracer {
        fn trace_call(&mut self, proc: CoreHandle) -> Result<(), UnknownError> {
            let pc = proc.cpu().pc()?;
            let name = self.symbols.get(&pc)
                .cloned()
                .unwrap_or_else(|| format!("sub_{:x}", pc));

            // Read arguments (ARM calling convention)
            let args: Vec<u32> = (0..4)
                .map(|i| proc.cpu().read_register(ArchRegister::from(i)))
                .collect::<Result<_, _>>()?;

            println!("{}-> {}({:#x}, {:#x}, {:#x}, {:#x})",
                     "  ".repeat(self.call_stack.len()),
                     name,
                     args[0], args[1], args[2], args[3]);

            self.call_stack.push((pc, name));
            Ok(())
        }

        fn trace_return(&mut self, proc: CoreHandle) -> Result<(), UnknownError> {
            if let Some((_, name)) = self.call_stack.pop() {
                let ret_val: u32 = proc.cpu().read_register(ArchRegister::R0)?;
                println!("{}<- {} returned {:#x}",
                         "  ".repeat(self.call_stack.len()),
                         name, ret_val);
            }
            Ok(())
        }
    }

Conditional Hooks
-----------------

Hooks that activate based on processor state:

.. code-block:: rust

    struct ConditionalHook<H> {
        condition: Box<dyn Fn(&CoreHandle) -> bool>,
        inner: H,
    }

    impl<H: MemoryWriteHook> MemoryWriteHook for ConditionalHook<H> {
        fn memory_write_hook(
            &mut self,
            proc: CoreHandle,
            address: u64,
            size: u32,
            data: &[u8],
        ) -> Result<(), UnknownError> {
            if (self.condition)(&proc) {
                self.inner.memory_write_hook(proc, address, size, data)?;
            }
            Ok(())
        }
    }

    // Usage: Only log when in supervisor mode
    let conditional = ConditionalHook {
        condition: Box::new(|proc| {
            proc.cpu().is_supervisor_mode().unwrap_or(false)
        }),
        inner: MyRealMemoryHook::new(),
    };

State Machine Hooks
-------------------

Implement protocol state machines:

.. code-block:: rust

    enum UartState {
        Idle,
        ReceivingCommand { bytes: Vec<u8>, expected: usize },
        SendingResponse { bytes: VecDeque<u8> },
    }

    struct UartStateMachine {
        state: UartState,
    }

    impl MemoryWriteHook for UartStateMachine {
        fn memory_write_hook(
            &mut self,
            proc: CoreHandle,
            address: u64,
            size: u32,
            data: &[u8],
        ) -> Result<(), UnknownError> {
            use UartState::*;

            self.state = match std::mem::take(&mut self.state) {
                Idle => {
                    if data[0] == 0xAA {  // Start byte
                        ReceivingCommand { bytes: vec![data[0]], expected: 8 }
                    } else {
                        Idle
                    }
                },
                ReceivingCommand { mut bytes, expected } => {
                    bytes.push(data[0]);
                    if bytes.len() >= expected {
                        let response = self.process_command(&bytes)?;
                        SendingResponse { bytes: response.into() }
                    } else {
                        ReceivingCommand { bytes, expected }
                    }
                },
                SendingResponse { mut bytes } => {
                    if let Some(byte) = bytes.pop_front() {
                        // Write response byte to RX buffer
                        proc.mmu().write_memory(0x40004804, &[byte])?;
                        proc.event_controller().trigger_interrupt(6)?;
                        SendingResponse { bytes }
                    } else {
                        Idle
                    }
                }
            };

            Ok(())
        }
    }


Gotchas
=======

1. **No Hook Recursion**: writes from ruse code will not trigger hooks to be fired

   .. code-block:: rust

       //  eg. when starting out, people assume this will trigger itself
       impl MemoryWriteHook for FirstHook {
           fn memory_write_hook(&mut self, proc: CoreHandle, address: u64, size: u32, data: &[u8])
               -> Result<(), UnknownError> {
               // This write **will not** trigger the same hook again!
               proc.mmu().write_memory(address, data)?;
               Ok(())
           }
       }

2. **Performance Impact**: Heavy computation in hooks

   If you're doing heavy computation, or File/Network I/O, you should put
   that functionality into a plugin.

   Inside your plugin, add the same hook, that then puts the data onto a
   queue or channel for the plugin to process. All plugins can create services
   on the embedded tokio runtime and execute in parallel to the main emulation threads.

See Also
========

* :ref:`plugins` - Building plugins with hooks
* :ref:`processors` - Processor implementation
* :ref:`custom_backends` - Custom execution backends
* ``examples/using-processor-hooks/`` - Complete hook examples
* ``styx/core/styx-processor/src/hooks/`` - Hook system source code
