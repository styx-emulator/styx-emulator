.. _debuggable_workflow:

Debuggable Emulation
####################

`gdb-multiarch` can be attached to a Styx emulator for debugging purposes.  This allows you to set breakpoints, single step execution, or use other useful GDB features while emulating with Styx.

Spawning a Processor with a GDB Executor
========================================

Build your processor as usual but make sure to use the ``GdbExecutor``.  The
example below shows adding a ``GdbExecutor`` to a PowerPC 405 processor. The
example is also available in ``examples/debugging-with-gdb``.


.. literalinclude:: ../../../examples/debugging-with-gdb/src/main.rs
    :lines: 2-
    :linenos:
    :language: rust


The ``GdbExecutor`` is a ``CustomExecutor``, so it is added with ``with_custom_executor()``. A complete, runnable version of this is in ``examples/debugging-with-gdb``.


Starting the Processor
======================

The processor should initialize and then wait for a connection from GDB.

.. code-block:: console

    styx-emulator$ cargo run -p debugging-with-gdb -- --firmware-path data/test-binaries/ppc/ppc405/bin/freertos.bin
        Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.39s
         Running `target/debug/debugging-with-gdb --firmware-path data/test-binaries/ppc/ppc405/bin/freertos.bin`
    ...
    Waiting for a GDB connection on "0.0.0.0:9999"...

Attaching and Running GDB
=========================

Using `gdb-multiarch`, connect to the remote server at 0.0.0.0:9999.  The following example shows
loading symbols from the matching elf, setting a breakpoint at ``main``, and then running until we
reach it.

.. code-block:: console

    styx-emulator$ gdb-multiarch
    GNU gdb (Ubuntu 15.1-1ubuntu1~24.04.1) 15.1
    Copyright (C) 2024 Free Software Foundation, Inc.
    License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.
    Type "show copying" and "show warranty" for details.
    This GDB was configured as "x86_64-linux-gnu".
    Type "show configuration" for configuration details.
    For bug reporting instructions, please see:
    <https://www.gnu.org/software/gdb/bugs/>.
    Find the GDB manual and other documentation resources online at:
        <http://www.gnu.org/software/gdb/documentation/>.

    For help, type "help".
    Type "apropos word" to search for commands related to "word".
    (gdb) file ./data/test-binaries/ppc/ppc405/bin/freertos.elf
    Reading symbols from ./data/test-binaries/ppc/ppc405/bin/freertos.elf...
    (gdb) target remote 0.0.0.0:9999
    Remote debugging using 0.0.0.0:9999
    warning: (Error: pc 0xfffffffc in address map, but not in symtab.)
    warning: (Internal error: pc 0xfffffffc in read in CU, but not in symtab.)
    0xfffffffc in _boot ()
    (gdb) b main
    Breakpoint 1 at 0xfff022a8: file main.c, line 182.
    (gdb) c
    Continuing.

    Breakpoint 1, main () at main.c:182
    warning: 182 main.c: No such file or directory
    (gdb) info registers pc
    pc             0xfff022a8          0xfff022a8 <main+20>


After Connecting to GDB
=======================

After Styx connects with GDB you should see a log message stating that GDB was
connected.

.. code-block:: console

    styx-emulator$ cargo run -p debugging-with-gdb -- --firmware-path data/test-binaries/ppc/ppc405/bin/freertos.bin
        Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.39s
         Running `target/debug/debugging-with-gdb --firmware-path data/test-binaries/ppc/ppc405/bin/freertos.bin`
    ...
    Waiting for a GDB connection on "0.0.0.0:9999"...
    Debugger connected from 127.0.0.1:43764


Most GDB functionality works. The following functionality is proven working.
Open an issue if it is not working as expected.

- Read/write registers
- Read/write memory
- Breakpoints
- Watchpoints (register, memory)

  - This known to have a significant performance impact [#perf-note]_

- Interrupt execution with ctrl-c
- Stop execution in Styx hooks via ``cpu.stop()``

Additionally, use `monitor` to access custom Styx functionality at the GDB command line. Use
this to interact with the emulator during debugging.

.. code-block:: console

    (gdb) monitor
    Styx custom commands to evaluate styx internals from gdb

    Usage: monitor [OPTIONS] <COMMAND>

    Commands:
      events  View and list events
      hooks   View and list hooks.
      help    Print this message or the help of the given subcommand(s)

    Options:
      -v, --verbose  Show backtraces on error
      -h, --help     Print help (see more with '--help')

Debugging a Multi-vCPU Processor
================================

The GDB executor works with multi-vCPU processors as well. In general, GDB
operates as if it is connected to a physical processor via debugging hardware.

That means each vCPU is presented to GDB as a thread, where the thread id is the
vCPU index plus one, so `info threads` lists one thread per core and `thread 2`
switches to the second core.

For breakpoints, a breakpoint is installed at the requested address on every
core, and the stop report names the thread that hit it.

All-Stop Mode
^^^^^^^^^^^^^

A known quirk to to GDB debugging in Styx
is that execution always has `all-stop mode
<https://sourceware.org/gdb/current/onlinedocs/gdb.html/All_002dStop-Mode.html>`
_ off. In short, this means that all cores can run when execution is resumed.
The option ``set scheduler-locking on`` is accepted but does nothing, all cores
continue or step regardless of the setting.

``examples/gdb-multicore-ppc`` is a two core PowerPC 405 processor that can be
used to try multi-core debugging out.

.. [#perf-note]
   Adding watchpoints requires the gdb executor to execute a single instruction
   at a time, instead of larger strides that improve emulation performance.

   The implementation can be found in
   ``styx/plugins/styx-gdbserver/src/target_impl.rs``
