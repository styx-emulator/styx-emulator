
.. _concepts:

Core Concepts
#############
.. mermaid::
    :caption: High-level block diagram of Styx components.

    graph TD
        subgraph emu [Emulator]
            code(Guest Code)
            subgraph proc [Processor]
                direction LR
                mem(MemoryBackend)
                evdist(EventDistributor)
                Peripherals
                subgraph vcpu ["VcpuCore [0..N]"]
                    mmu("MMU (tlb + phy mem ref)")
                    backend("CpuBackend")
                    time("VcpuTime")
                    evctl("EventController")
                end
            end
            evdist --> evctl
            mmu --> mem
            code --- proc
        end
        subgraph plugs [Plugins]
            styx-trace
            gdb-server
            styx-debug-tools
        end
        subgraph fe [Front Ends]
            styx-bin
            styx-daemon
            tools
        end
        emu --- plugs --- fe

Machine vs. CPU vs. Processor vs. Peripheral vs. Device
=======================================================

In ``Styx``, there are a few main abstractions over components of an emulated
device/cpu, because those terms are wildly overloaded the specific *thing* being
emulated is generally referred to as a **target system** or **system**.

The components of a **system** in ``Styx`` are known as:

.. _concepts_machine:

Machine
-------

A physical machine, made up of 1 or more ``Processor``'s and ``Device``'s
    * eg. a cell phone

.. _concepts_processor:

Processor
---------

A physical processor, made up of 1 or more ``CPU``'s, ``Peripheral``'s, and ``Device``'s
    * eg. ``STM32F746IE`` (an ARM Cortex M7 core manufactured by ST Microelectronics)


.. _concepts_cpu:

CPU
---

An individual CPU processor core, called a ``vCPU`` in ``Styx``, owning its own
execution engine (``CpuBackend``), ``Mmu``, and ``EventController``
    * eg. the ``CPU`` that executes instructions on the ``STM32F746IE``

The vCPU of a ``Processor`` share that ``Processor``'s physical memory
(``MemoryBackend``) and ``Peripheral``'s.


.. _concepts_peripheral:

Peripheral
----------

An onboard peripheral like a ``Timer``, ``GPIO``, ``UART``, ``PCI-e`` or ``DAC`` etc. that can communicate to 0 or more ``Device``'s
    * eg. the ``UART`` controller running on the ``STM32F746IE``

``Peripheral``'s belong to the ``Processor``, not to any one ``vCPU``. They are
owned by the processor-wide ``EventDistributor``, which routes the interrupts
they raise to the ``EventController`` of the appropriate ``vCPU``.


.. _concepts_device:

Device
------
A device or sensor that communicates or reports data to a ``CPU`` via a ``Peripheral``
    * eg. a ``GPS`` connected to ``UART0`` (a ``Peripheral``) of the ``STM32F746IE``,
      a ``Machine`` can also be treated as a ``Device`` connected to another ``Machine``

In a **system**, there can be multiple ``Machine``'s communicating with one another
executing concurrently. All executions of emulated machines happen concurrently and
all artifacts, tracing or otherwise can be correlated with a total order across all
emulated components.

This allows for full-system debugging, data flow, and taint-tracking analysis.

Emulation Layers
================

When creating tools and libraries for emulation its easier to think and reason about different
levels of abstraction. We try to stick to a format similar to the OSI model where we have 5
"levels" of emulation abstraction.

* :ref:`layer1`
* :ref:`layer2`
* :ref:`layer3`
* :ref:`layer4`
* :ref:`layer5`


.. _layer1:

Layer 1 - Bits and Bytes
------------------------

The individual bits and bytes of registers, memory, configuration registers etc.
An easy mental model of this is to think of a raw firehose stream of trace events:

    ``0x41414141`` written to ``0x42424242``

    ``0x9001`` written to ``R4``

    etc.

.. _layer2:

Layer 2 - Datatypes, Symbols, and Values
----------------------------------------

This level turn's the individual bits and bytes into something semantically labeled,
sometimes with an attached ``Datatype`` or ``Symbol``. For example,

    ``0x41414141`` written to ``task->state``

    ``RST | OPCODE_4 | UART0`` written to ``UART_CFG`` register

.. _layer3:

Layer 3 - Human Representation
------------------------------

Moving one level up in the hierarchy we get to the point where reasoning about things gets
a little more relatable or approachable from the layman's point of view.

    ``GPIO 15`` turned on", or ``Hello`` was printed to ``UART1``.

Or even crossing into lower levels (this example is ambiguously level 2 or 3):

    ``7.282348293488`` was written to ``task->stats->total_runtime``

A not super-formal-rule-of-thumb is "can this be modeled in some arbitrarily simple javascript/python" etc.
if the answer is yes (say like a push button you can click with a mouse, or a interactive terminal etc.),
then its probably ``Layer 3`` instead of 4.

.. _layer4:

Layer 4 - Isolated Component Model
----------------------------------

This level implies the ability to model or simulate a discrete system with this level of abstraction, eg.

    A user received "Hello world" as a text message

    The pedal was pushed, causing the vehicle speed to increase to 50mph

While these statements are more declaring what is happening, imagine a frontend dev or a graphics dev
making pretty models of a system that represents the above statement, they could, and its relatively
one arbitrary level of abstraction above ``Layer 3``, trust me |:wink:|


.. _layer5:

Layer 5 - Full System Model
---------------------------

This level is even more arbitrary than the last, and gets into not-super-well-explored territory.
But internally it can be equated to some level of MBSE (Model Based Systems Engineering) simulation
involving many systems working together to simulate an entire vehicle instead of just the dashboard,
for example. Or think of driving in a video game or flight simulator, except being grounded in
emulator of the microcontrollers and processors of the respective systems.

Hooks
=====

Target emulation revolves around the emulation of processors, and the instruction
emulation of various architectures. A system is nothing without it's connected components
and the communication between them. The simulated/emulated ``Device``'s communicate
to the onboard ``Peripheral``'s, which then pass data to the ``CPU`` via memory and
interrupts.

After an interrupt is asserted or memory is written (or both), the ``CPU`` will do
something with the data, and eventually write to memory somewhere else that will trigger
another interrupts to do something else. This entire process works via hooks that
modify and adjust the execution of the ``CPU`` instruction emulation.

In general there are only a couple variants of hooks:

* Memory R/W hooks
* Register R/W hooks
* PC-based hooks

Using Hooks
-----------

In terms of actually using the hooks, it requires only a mutable borrow of the
``CpuBackend`` in question and the hook itself, built with one of the ``StyxHook``
constructors.

For implementing a ``Peripheral`` callback for example, you might want to setup
a hook to get called every time address ``0x04000000`` gets written to, and
then call a method of a struct. Because Rust is Rust you can't directly do that
(the hook has to own the struct), so the process looks like:

.. code-block:: rust

    pub struct MyStruct(i32);

    impl MyStruct {
        // struct method to call - note the *immutable borrow*,
        // this is rust, so use *interior mutability*.
        fn my_callback(&self, data_written: Vec<u8>) {
            println!("{:?} was written to 0x04000000!", data_written);
        }
    }

    // the hook itself, owning whatever state the callback needs
    struct MyWriteHook(Arc<MyStruct>);

    impl MemoryWriteHook for MyWriteHook {
        fn call(
            &mut self,
            mut proc: CoreHandle,
            address: u64,
            size: u32,
            data: &[u8],
        ) -> Result<(), UnknownError> {
            println!("Hello from PC: @ {:x}", proc.pc()?);

            self.0.my_callback(data.to_vec());
            Ok(())
        }
    }

    // in `Peripheral::init()`, where the peripheral is handed the building processor
    fn register_hooks(cpu: &mut dyn CpuBackend, state: Arc<MyStruct>) -> Result<(), UnknownError> {
        cpu.add_hook(StyxHook::memory_write(0x04000000..=0x04000004, MyWriteHook(state)))?;
        Ok(())
    }

The callback trait in question, and the blanket implementation that lets a plain
function or closure be used in its place, i.e.:

.. code-block:: rust

    /// This implements MemoryWriteHook
    fn my_memory_write_hook(core_handle: CoreHandle, address: u64, size: u32, data: &[u8]) -> Result<(), UnknownError> {
        /* ... */
    }

Note that the ``CoreHandle`` is a handle to the currently executing emulated
``vCPU`` and gives access to its ``CpuBackend``, ``Mmu``, and ``EventController``, useful for grabbing CPU state when you need it.
