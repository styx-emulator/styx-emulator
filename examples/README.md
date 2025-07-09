# Examples

These are a set of examples for the `styx-emulator`, feel free to add new benchmarks for new
features as they are added and document what the example is doing so that other people can
benefit from the additions. Enjoy.

**Python** examples are located in **styx/bindings/styx-py-api/examples**  
**C** examples are located in **styx/bindings/styx-c-api/examples**

## List of Examples

1. [Using a Processor](#using-a-processor)
2. [Using Processor Hooks](#using-processor-hooks)
3. [Multiple Processors (manual)](#working-with-multiple-processors-manually)
4. [Debugging a TargetProgram via GDB server](#debugging-a-targetprogram-with-gdb-server)
5. [Kinetis21 angr Interrupt Analysis](#kinetis21-angr-interrupt)
6. [Working with a RawProcessor (Unicorn equivalent)](#working-with-rawprocessor)
7. [PPC405 FreeRTOS Instrumentation Example](#ppc405-freertos-instrumentation)
8. [DIY Processor Example](#diy-processor)
9. [Using styx-devices](#working-with-styx-devices)
10. [DIY styx-device](#diy-styx-device)
11. [Fuzzer Plugin Example](#using-the-fuzzer-plugin)
12. [Adding an External Cpu Backend](#adding-an-external-backend)

.. _using-a-processor:

### Using a Processor

Path: `./using-a-processor`

This is a simple example of using a `Processor`, this example starts a `Processor` and
logs output to the console.

.. _using-processor-hooks:

### Using Processor Hooks

Path: `./using-processor-hooks`

This example creates a `Processor` and adds some hooks to instrument + log the behavior
of the `TargetProgram` at runtime.

.. _working-with-multiple-processors-manually:

### Working with Multiple Processors (Manually)

Path: `./multiple-processors`

This example shows off a manual implementation of multiple communicating `Processor`'s.
Both of these `Processor`'s are taking advantage of `styx-trace` for deep runtime instrumentation,
and connects the two `Processor`'s via `UART`. Note that Neither `Processor` is using the
`ProcessorTracingPlugin`. Both `Processor`'s are in the same process so that plugin would
cause runtime panic due to limitations of Rust `log`+`tracing` crates. To more easily
use multiple processors spawn them in different processes entirely (or use the in-tree
workspaces + utilities for orchestrating emulation execution).

**Where's the TargetProgram's?**  
In transitioning of codebases the `TargetProgram` for each processor was lost, apologies.
Thankfully the code was trivial and `Primary` sent bytes and asserted that they were echoed
by the `TargetProgram` running a UART2~echo server on `Secondary`.

.. _debugging-a-targetprogram-with-gdb-server:

### Debugging a TargetProgram with GDB server

Path: `./debugging-with-gdb`

This example shows how you add the `GdbExecutor` to a `ProcessorBuilder` to debug a `TargetProgram`
under gdb.

.. _kinetis21-angr-interrupt:

### Kinetis21 angr Interrupt

Path: `./kinetis21-interrupt-angr`

This example showcased usage of angr on multiple processors to get through a simple
crackme style challenge that traversed multiple `TargetProgram`'s.

.. _working-with-rawprocessor:

### Working with RawProcessor

Path: `./raw-processor`

This example is to showcase the similarities between the `RawProcessor` and a Unicorn example,
`RawProcessor`'s have no interrupts, and only execute code based on a `ArchitectureVariant`
and a `Backend`.

.. _ppc405-freertos-instrumentation:

### PPC405 FreeRTOS Instrumentation

Path: `./ppc405-freertos-demo`

This example shows the use of a custom tui to instrument + show the progress of the ancient
PPC405 FreeRTOS kitchen-sink style example firmware for the `TargetProgram`.

.. _diy-processor:

### DIY Processor

Path: `./diy-processor`

**NOTE**: this example is not accurate, please see definitions of things like `Stm32f107` in
the repository under `./styx/processors/arm/stm32f107-processor`

This example shows how to make a DIY Processor that you can use standalone, or upstream
to the `styx-emulator` codebase :slight_smile:.

.. _working-with-styx-devices:

### Working with styx-devices

Path: `./styx-devices`

This example shows how you can import and use premade device's and connect them to a
peripheral bus of an emulator.

.. _diy-styx-device:

### DIY styx-device

Path: `./talking-to-peripherals`

This is a DIY device example. Since a device is anything that talks to an emulators'
peripheral bus it start easy (but can quickly balloon) to make your own to suit your needs!

.. _using-the-fuzzer-plugin:

### Using the Fuzzer Plugin

Path: `./fuzzer-plugin`

This example is a end-to-end example of using the `FuzzerPlugin`. This is a complex plugin
that utilizes the `styx-trace` deep instrumentation bus to steer fuzzing based on coverage
reports. This plugin requires some `TargetProgram` pre-processing with an Ghidra script
to produce a usable list of coverage points to measure.

.. _adding-an-external-backend:

### Adding an External Cpu Backend

Path: `./external-backend`

This example showcases creating a custom CPU Backend by implementing the CpuBackend trait.
