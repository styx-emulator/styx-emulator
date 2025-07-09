# Fuzzer Plugin Example

This example is a end-to-end example of using the `FuzzerPlugin`. This is a complex plugin
that utilizes the `styx-trace` deep instrumentation bus to steer fuzzing based on coverage
reports. This plugin requires some `TargetProgram` pre-processing with an Ghidra script
to produce a usable list of coverage points to measure.

## Quick Start

```console
$ cargo run
...
client sending test data
Reached end of fuzz-case seed test
[UserStats #0] run time: 0h-0m-0s, clients: 1, corpus: 0, objectives: 0, executions: 0, exec/sec: 0.000
[Testcase #0] run time: 0h-0m-0s, clients: 1, corpus: 1, objectives: 0, executions: 1, exec/sec: 0.000
[UserStats #0] run time: 0h-0m-0s, clients: 1, corpus: 1, objectives: 0, executions: 1, exec/sec: 0.000
[Testcase #0] run time: 0h-0m-0s, clients: 1, corpus: 2, objectives: 0, executions: 243, exec/sec: 0.000
[UserStats #0] run time: 0h-0m-0s, clients: 1, corpus: 2, objectives: 0, executions: 243, exec/sec: 0.000
[Testcase #0] run time: 0h-0m-0s, clients: 1, corpus: 3, objectives: 0, executions: 577, exec/sec: 0.000
[UserStats #0] run time: 0h-0m-0s, clients: 1, corpus: 3, objectives: 0, executions: 577, exec/sec: 0.000
[Testcase #0] run time: 0h-0m-0s, clients: 1, corpus: 4, objectives: 0, executions: 2018, exec/sec: 0.000
[UserStats #0] run time: 0h-0m-1s, clients: 1, corpus: 4, objectives: 0, executions: 2018, exec/sec: 0.000
[Testcase #0] run time: 0h-0m-1s, clients: 1, corpus: 5, objectives: 0, executions: 4586, exec/sec: 0.000
[UserStats #0] run time: 0h-0m-2s, clients: 1, corpus: 5, objectives: 0, executions: 4586, exec/sec: 1.874k
[Testcase #0] run time: 0h-0m-2s, clients: 1, corpus: 6, objectives: 0, executions: 22467, exec/sec: 9.182k
```

## Fuzzer Interface

To run with the LibAFL TUI (enhanced UI based on ratatui), enable the `tui` feature.

```console
cargo run --features tui
```

## Debug Logging

To change the logging level, use the `RUST_LOG` environment variable.

```console
RUST_LOG=info cargo run
```
