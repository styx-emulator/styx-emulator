
.. _concepts:

Core Concepts
#############
.. mermaid::
    :caption: High-level block diagram.

    graph TD
        subgraph emu [Emulator]
            direction LR
            code(Guest Code)
            subgraph proc [Processor]
                cpu(CPU Engine)
                evctl(Event Controller)
                Peripherals
            end
            code --- proc
        end
        subgraph plugs [Plugins]
            styx-trace
            gdb-server
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

An individual CPU processor core, containing 1 or more ``Peripheral``'s and ``Device``'s
    * eg. the ``CPU`` that executes instructions on the ``STM32F746IE``



.. _concepts_peripheral:

Peripheral
----------

An onboard peripheral like a ``Timer``, ``GPIO``, ``UART``, ``PCI-e`` or ``DAC`` etc. that can communicate to 0 or more ``Device``'s
    * eg. the ``NVIC`` event controller running on the ``STM32F746IE``, or the ``UART`` controller etc.


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

A Note on cleanliness
---------------------

In ``Styx``, all hooks have a "normal" and "userdata" variant (at the moment). Due to
Rust being a (notoriously) strongly-typed language, creating a super clean and
ergonomic callback/hook system with asynchronous state is not the easiest thing to do
well. Due to the ``Styx`` project being overly immature, getting user-facing features
as opposed to a super clean developer API is the main concern, so we have settled
with an API that exposes two flavors of each hook, with the knowledge that at some
point in the future we'll have the time/capacity/need to go back and update it to
a more modern `Extractor` style pattern or something.

That being said, they get the job done, and are not that bad to work with, save for
the extra ``userdata.downcast_ref::<TypeToCastTo>()`` that makes up the first line
of all the userdata callbacks.

Using Hooks
-----------

In terms of actually using the hooks, it requires only an immutable borrow the
the ``CpuBackend`` in question, a ``Box`` of the hook function, and an ``Arc`` of
the object to pass as user data to the callback.

For implementing a ``Peripheral`` callback for example, you might want to setup
a function to get called every time address ``0x04000000`` gets written to, and
then call a method of a struct. Because Rust is Rust you can't directly do that
(you need a proxy method), so the process looks like:

.. code-block:: rust

    pub struct MyStruct(i32);

    impl MyStruct {
        // struct method to call - note the *immutable borrow*,
        // this is rust, so use *interior mutability*.
        fn my_callback(&self, data_written: Vec<u8>) {
            println!("{:?} was written to 0x04000000!", data_written);
        }
    }

    // callback proxy function - must adhere to the callbackFn definition
    // -- see next rust block
    fn my_proxy_write_memory(cpu: &CpuBackend, address: u64, size: u32, data: &[u8], userdata: HookUserData) {
        let my_struct = userdata.downcast_ref::<MyStruct>().unwrap();
        println!("Hello from PC: @ {x}", cpu.pc());

        my_struct.my_callback(data.to_vec());
    }

    // in main setup of the Processor
    fn register_hooks(cpu: &CpuBackend) {
        cpu.mem_write_hook_data(0x04000000,
                                0x04000004,
                                Box::new(my_proxy_write_memory),
                                Arc::new(MyStruct));
    }

The ``callbackFn`` type signatures in question (normal + userdata variant):

.. code-block:: rust

    /// Userdata type passable to all callbacks accepting userdata.
    pub type HookUserData = Arc<dyn Any + Sync + Send + 'static>;

    /// Callback fn type for memory writes, arguments are:
    /// - `&CpuBackend`
    /// - `address: u64`
    /// - `size: u32`
    /// - `data: &[u8]`
    pub type MemWriteCBType = Box<dyn FnMut(&CpuBackend, u64, u32, &[u8])>;

    /// Callback fn type for memory writes, arguments are:
    /// - `&CpuBackend`
    /// - `address: u64`
    /// - `size: u32`
    /// - `data: &[u8]`
    /// - `userdata`
    pub type MemWriteDataCBType = Box<dyn FnMut(&CpuBackend, u64, u32, &[u8], HookUserData)>;

Note that the ``CpuBackend`` is a handle to the currently executing emulated
``CPU`` and is useful for grabbing internal state when you need it.
