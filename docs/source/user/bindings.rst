.. _bindings:

Bindings
########

Styx offers API bindings for both Python and C.

Python Bindings
===============

Styx provides Python bindings of a portion of its API to enable developers to quickly develop on top of the Styx Emulator library.

Installation
------------

Styx Python bindings are available as a Python wheel. Use your favorite python package manager to install from sources, preferably in a virtual environment. Bulding the wheel requires rust, clang, cmake, protoc, and libprotobuf-dev to be installed.

.. code-block:: console

    python3 -m virtualenv venv
    . venv/bin/activate
    pip install ./styx/bindings/styx-py-api/


Examples
--------
Two examples are available in ``./styx/bindings/styx-py-api/examples/``.

* simple-stm32f107

  * Building and starting an ARM processor with a single code hook.

* uart-kinetis21

  * ARM processor with UART communication, instruction counting, and basic block tracking.


Getting Started
---------------

The ``styx_emulator`` package is organized into modules. The root ``styx_emulator`` module has no functions or classes associated with it. The following modules are available:

.. code-block::

    processor
      - Processor, ProcessorBuilder
    cpu
      - CpuBackend, ArchEndian
    cpu.hooks
      - hook definitions
    cpu.arch
      - Arch enum
    cpu.arch.arm
      - ARM registers and variants
    cpu.arch.ppc32
      - PowerPC32 registers and variants
    cpu.arch.blackfin
      - Blackfin registers and variants
    cpu.arch.superh
      - SuperH registers and variants
    executor
      - executors
    loader
      - firmware/program loaders
    plugin
      - processor plugins
    peripherals
      - peripheral clients
    angr
      - angr integration

For a minimal example, we'll first import some basic classes.

.. code-block:: python

    from styx_emulator.cpu import ArchEndian, Backend, CpuBackend
    from styx_emulator.cpu.hooks import CodeHook
    from styx_emulator.processor import ProcessorBuilder, Target
    from styx_emulator.loader import RawLoader
    from styx_emulator.executor import DefaultExecutor
    from styx_emulator.arch.arm import ArmVariant
    from styx_emulator.plugin import ProcessorTracingPlugin


To create a processor, use the `ProcessorBuilder` class. The api is similar to the Rust api, instead using setters on attributes. The builder allows you to configure aspects of the cpu and how it will connect to outside peripherals.

.. code-block:: python

    TARGET_PROGRAM = "../../../../../data/test-binaries/arm/kinetis_21/bin/freertos_hello/freertos_hello_debug.bin"

    # create a new processor builder
    builder = ProcessorBuilder()

    builder.endian = ArchEndian.LittleEndian
    builder.target_program = TARGET_PROGRAM
    builder.ipc_port = 16001
    builder.loader = RawLoader()
    builder.executor = DefaultExecutor()
    builder.variant = ArmVariant.ArmCortexM4
    builder.backend = Backend.Unicorn
    builder.add_plugin(ProcessorTracingPlugin())
    # build the processor
    proc = builder.build(Target.Kinetis21)

``proc`` now holds a built ``Processor`` for you to use for emulation. At this point you can use ``proc.start()`` to start emulating. We have no hooks yet though so it would be uninteresting.

This target program is a FreeRTOS example that sends "Hello World\\r\\n" through the serial debug port (UART port 5 to be exact). To see this in action, let's define a **hook callback** on the ``IO_Transfer`` function to print the character that's being sent. Hook callbacks are simply python functions with specific signatures that are called when an event happens in the processor. They are analogous to hooks in the Rust api.

The signature for a code hook is.

.. code-block:: python

    CodeHook(start: int, end: int, callback: Any)

Styx will execute the passed ``callback`` with a single argument ``CpuBackend`` when the cpu executes an instruction in the address range ``(start, end]``.

Let's add our code hook.

.. code-block:: python

    IO_TRANSFER_ADDR = 0x00001AE8
    def io_transfer(cpu: CpuBackend):
        """
        Code hook, called when target transfers serial character data.

        Used to show when target sends UART message over the line.
        """
        # character to send stored in r2
        c = cpu.read_register("r2")
        if c:
            print(f"target sent {c.to_bytes(1)}")
        else:
            print("no register r2 in target")


    proc.add_hook(CodeHook(IO_TRANSFER_ADDR, IO_TRANSFER_ADDR, io_transfer))

This made a code hook that triggers when the processor's program counter is in the range ``(0x00001AE8, 0x00001AE8]``, which simplifies to the single address ``0x00001AE8``. ``CodeHook`` is just one example of a hook, the other hooks currently available in the python bindings are listed below:

* CodeHook

  * Triggered on execution in a range of program counter addresses.

* BlockHook

  * Triggered on hitting a new basic block.

* MemWriteHook

  * Called on a memory write to a range of addresses.

* MemReadHook

  * Called on a memory read to a range of addresses.

* InterruptHook

  * Called on an cpu interrupt triggered.

* InvalidInsnHook

  * Called on an invalid instruction encountered


The hook callbacks can have different signatures.
(
To run the processor:

.. code-block:: python

    proc.start()

This blocks the current python execution thread but allows multithreaded Python code to run while the cpu is executing. This code and more is available in the ``uart-kinetis21`` styx-py-api example.


Peripherals
-----------

Some styx peripherals are included as python bindings for easy use. Currently only the UartClient is available.


.. code-block:: python

    DEBUG_UART_PORT = 5
    IPC_PORT = 16001
    client = UartClient(f"http://127.0.0.1:{IPC_PORT}", DEBUG_UART_PORT)

    # check if any bytes are received
    num_bytes_to_check = 1
    recv_bytes = client.recv_nonblocking(num_bytes_to_check)
    if recv_bytes != None:
        print("got a byte!")

    # send some bytes over the line
    client.send(b'Hello again\n').

The ``UartClient`` will throw an exception if it could not connect.

Symbion
-------

Angr Symbion allows interleaved analysis of concrete and symbolic execution. In this setup, Styx can complete concrete execution of of complex initialization or external state (peripherals) and then use angr's symbolic execution to complete the analysis.

Symbion support for Styx in an experimental stage. Check out ``styx/bindings/styx-py-api/styx_symbion`` and the current example ``styx/bindings/styx-py-api/styx_symbion/tests/test1.py``.
