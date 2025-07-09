# Using Processor Hooks

Hooks are one of the core features of Styx. This example creates a `Processor` and adds some hooks
to instrument + log the behavior of the `TargetProgram` at runtime.

## Quick Start

```console
$ cd examples/using-processor-hooks
$ cargo run --bin proc
initial PC: 0x1708
CPU started, pc = :[ 0x3d0]
reading from cr1!
reading from cr1!
writing to cr1!
reading from cr1!
writing to cr1!
reading from cr1!
reading from cr1!
writing to cr1!
```

From another terminal:

```console
$ cd examples/using-processor-hooks
$ cargo run --bin user
waiting for localhost:16000 ...
client created
----------
Type a single character to send to the STM32F405:
```

Send a character from the `user` terminal and watch the `proc` terminal print some information on
what it is doing including calling the "uart receive data" function, calling the "send uart byte"
function, and writing to the "uart data read" register.

The informational data from the `proc` log are triggered via processor hooks.
