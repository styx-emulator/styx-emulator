# Multiple Processors Example

DISCLAIMER: this example does not run at the moment because of lost target programs.

This example shows off a manual implementation of multiple communicating `Processor`'s.
Both of these `Processor`'s are taking advantage of `styx-trace` for deep runtime instrumentation,
and connects the two `Processor`'s via `UART`.

**Where's the TargetProgram's?**  
In transitioning of codebases the `TargetProgram` for each processor was lost, apologies.
Thankfully the code was trivial and `Primary` sent bytes and asserted that they were echoed
by the `TargetProgram` running a UART2~echo server on `Secondary`.

## Quick Start

```console
cargo run
```

## Tracing

Note that Neither `Processor` is using the
`ProcessorTracingPlugin`. Both `Processor`'s are in the same process so that plugin would
cause runtime panic due to limitations of Rust `log`+`tracing` crates. To more easily
use multiple processors spawn them in different processes entirely (or use the in-tree
workspaces + utilities for orchestrating emulation execution).
