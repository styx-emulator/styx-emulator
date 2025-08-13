.. _debuggable_workflow:

Debuggable Emulation
####################

`gdb-multiarch` can be attached to a Styx emulator for debugging purposes.  This allows you to set breakpoints, single step execution, or use other useful GDB features while emulating with Styx.

Spawning a Processor with a GDB Executor
========================================

Build your processor as usual but make sure to use the `GdbExecutor`.  The example below shows adding a Gdb executor to a Kinetis21 processor.

.. code-block:: rust

    use clap::Parser;

    use styx_core::prelude::*;
    use styx_core::processor::executor::Executor;
    use styx_core::cpu::arch::arm::ArmVariants;
    use styx_core::cpu::arch::arm::gdb_targets::Armv7emDescription;
    use styx_core::cpu::{ArchEndian, Backend};
    use styx_plugins::gdb::{GdbExecutor, GdbPluginParams};
    use styx_loader::RawLoader;
    use styx_processors::arm::kinetis21::Kinetis21Cpu;

    #[derive(Debug, Parser)]
    #[command(author, version, about, long_about = None)]
    struct TargetArgs {
        /// Path to the target firmware `.bin`, required.
        #[arg(short, long)]
        firmware_path: String,
    }

    fn main() -> Result<(), UnknownError> {
        let args = TargetArgs::parse();

        let gdb_params = GdbPluginParams::tcp("0.0.0.0", 9999, true);

        let builder = ProcessorBuilder::default()
            .with_endian(ArchEndian::LittleEndian)
            .with_executor(
                Executor::new_unlimited(
                    Arc::new(GdbExecutor::<Armv7emDescription>::new(gdb_params))
                )
            )
            .with_backend(Backend::Pcode)
            .with_loader(RawLoader)
            .with_target_program(args.firmware_path)
            .with_variant(ArmVariants::ArmCortexM4);

        let proc = builder.build::<Kinetis21Cpu>()?;

        proc.start()?;

        Ok(())
    }

Starting the Processor
======================

The processor should initialize and then wait for a connection from GDB.

.. code-block:: console

    styx-emulator/examples/kinetis21-processor$ cargo run -- --firmware-path ../../data/test-binaries/arm/kinetis_21/bin/hello_world/hello_world_debug.bin
        Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.30s
        Running `styx-emulator/target/debug/kinetis21-processor --firmware-path ../../data/test-binaries/arm/kinetis_21/bin/hello_world/hello_world_debug.bin`
    Waiting for a GDB connection on "0.0.0.0:9999"...


Attaching and Running GDB
=========================

Using `gdb-multiarch`, connect to the remote server at 0.0.0.0:9999.  The following example shows loading symbols from an elf, setting a breakpoint at main, and then running until we reach it.

.. code-block:: console

    styx-emulator$ gdb-multiarch
    GNU gdb (Ubuntu 15.0.50.20240403-0ubuntu1) 15.0.50.20240403-git
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
    (gdb) file ./data/test-binaries/arm/kinetis_21/bin/hello_world/hello_world_debug.elf
    Reading symbols from ./data/test-binaries/arm/kinetis_21/bin/hello_world/hello_world_debug.elf...
    (gdb) target remote 0.0.0.0:9999
    Remote debugging using 0.0.0.0:9999
    Reset_Handler () at /home/ubuntu/sm/styx-emulator/data/test-binaries/arm/kinetis_21/twrk21f120m-sdk/devices/MK21FA12/gcc/startup_MK21FA12.S:330
    warning: 330 /home/ubuntu/sm/styx-emulator/data/test-binaries/arm/kinetis_21/twrk21f120m-sdk/devices/MK21FA12/gcc/startup_MK21FA12.S: No such file or directory
    (gdb) b main
    Breakpoint 1 at 0xc06: file /home/ubuntu/sm/styx-emulator/data/test-binaries/arm/kinetis_21/twrk21f120m-sdk/boards/twrk21f120m/demo_apps/hello_world/hello_world.c, line 111.
    (gdb) c
    Continuing.

    Breakpoint 1, main () at /home/ubuntu/sm/styx-emulator/data/test-binaries/arm/kinetis_21/twrk21f120m-sdk/boards/twrk21f120m/demo_apps/hello_world/hello_world.c:111
    warning: 111 /home/ubuntu/sm/styx-emulator/data/test-binaries/arm/kinetis_21/twrk21f120m-sdk/boards/twrk21f120m/demo_apps/hello_world/hello_world.c: No such file or directory
    (gdb)


After Connecting to GDB
=======================

After Styx connects with GDB you should see a log message stating that GDB was
connected.

.. code-block:: console

    styx-emulator/examples/kinetis21-processor$ cargo run -- --firmware-path ../../data/test-binaries/arm/kinetis_21/bin/hello_world/hello_world_debug.bin
        Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.30s
        Running `styx-emulator/target/debug/kinetis21-processor --firmware-path ../../data/test-binaries/arm/kinetis_21/bin/hello_world/hello_world_debug.bin`
    Waiting for a GDB connection on "0.0.0.0:9999"...
    Debugger connected from 127.0.0.1:40408


Most GDB functionality works. The following functionality is proven working.
Open an issue if it is not working as expected.

- Read/write registers
- Read/write memory
- Breakpoints
- Watch points
- Watch registers

  - This known to have a significant performance impact

- Interrupt execution with ctrl-c
- Stop execution in Styx hooks via ``cpu.stop()``

Additionally, use `monitor` to access custom Styx functionality at the GDB command line. Use
this to interact with the emulator during debugging.

.. code-block:: console

    (gdb) monitor
    Styx custom commands to evaluate styx internals from gdb

    Usage: monitor [OPTIONS] <COMMAND>

    Commands:
      hooks   View and list hooks.
      events  View and list events
      help    Print this message or the help of the given subcommand(s)

    Options:
      -v, --verbose  Print backtraces on error
      -h, --help     Print help (see more with '--help')
