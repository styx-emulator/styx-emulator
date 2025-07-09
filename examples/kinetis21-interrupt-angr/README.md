
# Kinets21 Interrupt Analysis

this example uses Angr with Styx to do program analysis across UART5 between a `proc` and `hackme` binary.

# Angr Example

The angr example serves to demonstrate how Styx can be used as a concrete engine alongside Angr as a symbolic one.

Both angr scripts [./proc.py](./proc.py) and [./hackme.py](./hackme.py) are well documented, reading through them
should provider some insight into how analysis is done

```console
$ python hackme.py &  # start hackme in the background as it waits on proc.py
$ python proc.py
```

# Working Example

The working example exists to show how the binaries should work under normal conditions. The entrypoint is [client.rs](client.rs).

- `PROC_TRACE="trace|debug|info|warn|error"` controls the log level for PROC_TRACE
- `HACKME_TRACE="trace|debug|info|warn|error"` controls the log level for HACKME_TRACE
  - *NOTE*, only ***1*** of these can be specified to do log initialization in the ProcessorTracingPlugin
