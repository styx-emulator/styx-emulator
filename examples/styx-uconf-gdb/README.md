# Unified Configuration with GDB

This examples shows Styx's Unified Configuration by running a processor with GDB integration. The
example instantiates a ppc405 processor and loads some freertos firmware.

## Quick Start

In one terminal, run a freertos binary.

```console
$ cd examples/debugging-with-gdb
$ cargo run --manifest-path ../../incubation/styx-uconf-cli/Cargo.toml -- run
...
Waiting for a GDB connection on "0.0.0.0:9999"...
```

In another terminal, connect with gdb-multiarch.

```console
$ gdb-multiarch
(gdb) set endian big
(gdb) target remote :9999
Remote debugging using :9999
0xfffffffc in ?? ()
(gdb)
```

Now you can interact with the target as you would any other GDB target.

## Use the Styx Monitor CLI

The Styx GDB server includes a custom `monitor` command interface to interact with the Styx Emulator
from GDB. Use the built in help to see what it can do.

```console
(gdb) monitor --help
Styx custom commands to evaluate styx internals from gdb.

The Styx "monitor" commands can be used to view Emulator internals such as hooks, event controller, peripheral status, etc. from the gdb console. Using this can aid debugging by providing introspection into running processor internals.

Usage: monitor [OPTIONS] <COMMAND>

Commands:
  hooks   View and list hooks.
  events  View and list events
  help    Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose
          Show backtraces on error

  -h, --help
          Print help (see a summary with '-h')
```
