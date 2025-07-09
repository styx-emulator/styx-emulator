# Multiple Processors Example

This example shows the use of a custom tui to instrument + show the progress of the ancient
PPC405 FreeRTOS kitchen-sink style example firmware for the `TargetProgram`.

## Quick Start

```console
cd examples/ppc405-freertos-demo
cargo run --release
```

## What am I Looking At

The target firmware is FreeRTOS, a realtime operating system built for all types of embedded
systems. A responsibility of an RTOS is to manage multiple tasks (think threads) and guarantee
certain execution time requirements. To do this, FreeRTOS runs on "ticks" that are incremented
periodically by the chip's timer. Each tick interrupts the current task's execution and presents the OS an opportunity to switch tasks.

The top left box introspects these the internals of the FreeRTOS system by displaying the current
program counter (PC), the current tick, the next tick where the task with switch, and the current
task name and priority.

This firmware more specifically is a test image that tests many FreeRTOS and board features. Test
tests are run as tasks in the system and are listed in the box in the middle of left column. The
tests are initially unchecked and are run every 3000 ticks. Waiting for the current tick to hit 3000
will trigger the test task to check all running tests. Without sending UART data, all tests will
succeed except for the UART/Coms test.

The UART/Coms test will succeed if the UART task has received the characters A-X before the test is
run (at increments of 3000 ticks). Press the space bar to send one of these characters. The total
characters received, received characters in this testing loop, text received are shown on the bottom
left box.

The right side box shows a the logging of the Styx Emulator.
