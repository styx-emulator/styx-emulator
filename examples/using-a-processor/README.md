# Using a Processor

This example loads and emulates the execution of a FreeRTOS system for the Kinetis21 board.

## Quick Start

```console
$ cd examples/using-a-processor
$ cargo run
...
DEBUG styx_nvic: Restored stack: frame size: 32, frame ptr: 0x1fff0448, 8 byte stack alignment: true
DEBUG styx_nvic::hooks: Returning from exception IRQ_-2 -> 0x00000c5c
DEBUG styx_kinetis21_processor::uart::hooks: Guest read from UART5 S1: S1 { pf: 0, fe: 0, nf: 0, or: 0, edle: 0, rdrf: 0, tc: 1, tdre: 1 }
DEBUG styx_kinetis21_processor::uart::hooks: Guest wrote to UART5 D: 72 from: 0x001ae8
DEBUG styx_kinetis21_processor::uart: guest transmit data 72
DEBUG styx_kinetis21_processor::uart::hooks: Guest read from UART5 S1: S1 { pf: 0, fe: 0, nf: 0, or: 0, edle: 0, rdrf: 0, tc: 1, tdre: 1 }
DEBUG styx_kinetis21_processor::uart::hooks: Guest wrote to UART5 D: 101 from: 0x001ae8
```

## Debug Logging

To change the logging level, use the `RUST_LOG` environment variable.

```console
RUST_LOG=info cargo run
```

## Tracing

To run with PC, memory read and memory write tracing, turn the "trace" feature on. e.g.

```console
cargo run --features trace
```
