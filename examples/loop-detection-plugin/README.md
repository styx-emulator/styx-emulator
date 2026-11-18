# Loop Detection Plugin Example

Demonstrates `LoopDetectionPlugin` from `styx-debug-tools`: it reports a loop
once it has iterated at least a configured number of times, and attributes each
loop to the stack frame it runs in.

## Run

```sh
cargo run -p loop-detection-plugin
```

It emulates an STM32F107 running a small GPIO "blink" firmware on the **pcode**
backend, then stops at the first loop that reaches the threshold (5 iterations)
and prints a report.

> Loop detection requires the pcode backend's control-flow classification — it
> does **not** work on the Unicorn backend.

## Changing variables to understand the plugin

- Set `halt_on_detection` to `false` and bound the run by an instruction count
  (`proc.run(2_000_000u64)`) to observe multiple loops instead of stopping at
  the first one.
- Pair the detector with a `ShadowStackPlugin` (added *before* the loop
  detector, so its hook runs first) and pass that plugin's handles
  (`ShadowStackPlugin::new(vcpu_count).clone_handles()`) to
  `LoopDetectionPlugin::with_shadow_stacks`. You can then read a stack trace
  (`handles[vcpu_id].bottom_to_top()`) inside your callback to print the call
  chain a loop was detected in.
