# Unicorn Replacement

This example uses `Styx` purely as a CPU emulator, the way `Unicorn` is normally used.

It assembles four Thumb instructions with `keystone`, loads the resulting bytes into a
`RawProcessor` for 32 bit Arm, and traces execution with instruction and interrupt hooks.
The `SVC #0` instruction raises an interrupt to stop the emulation with a hook. The
example then reads `r2` to confirm that the multiply ran.

Run it with:

```shell
cargo run -p unicorn-replacement
```

The equivalent Python example is in
`styx/bindings/styx-py-api/examples/unicorn-replacement/main.py`.
