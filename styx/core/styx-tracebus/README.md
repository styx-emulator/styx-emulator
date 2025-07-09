# Styx Trace

This library package implements a tracing facility for programattically eminating events during emulation. Like logging, but optimized on the qualities we care about:

- Don't slow down emulation
- High volume / throughput (events per unit of time)
- Low memory usage per event (eg low resource util)
- Multi-process (event readers can be in a different process than the event writer)
- Extensible event list
- Easy to use API

## styx-trace package contents

- **lib.rs** has a trace interface using rust idioms (traits, structs, macros) and a set of Events.
- **ipc_impl.rs** is an implementation of the interface leveraging [ipmpsc::SharedRingBuffer](https://docs.rs/ipmpsc/0.5.1/ipmpsc/).
- **strace.rs** is a _cli_ utility for reading the trace buffers. It also contains an option for generating events, for testing.

## Design / Implementation Notes

The `SharedRingBuffer` implementation uses a a memory-mapped file, [memmap2](https://docs.rs/memmap2/latest/memmap2/#), for inter-process communication (IPC), and:

- A [sender](https://docs.rs/ipmpsc/0.5.1/ipmpsc/struct.Sender.html) sends messages (writes to the buffer)
- A [receiver](https://docs.rs/ipmpsc/0.5.1/ipmpsc/struct.Receiver.html) receives (opens file, reads) uses a memory mapped file with a ring buffer algo. the `Sender` can send (ie write to the buffer), the `Receiver`

Note: the receiver does not memcpy - it uses a zero copy context, ie just returns an interpreted pointer to the item.

## Trace Abstraction

The macro `strace!(event)` is used to write an event, where `event` must be an impl of trait `Traceable`. All events must provide `impl Traceable` and be fixed-sized (`size_of<BaseTestEvent>`).  _(Currently 24 bytes if numbered, 16 otherwise)_. Things won't compile otherwise.

Adding new events is a 2-item process:

1. Define the event
2. Add the event to the dispatch list

For defining the event, there is a helper macro,  `styx_event`. All new events _must_ be the same size (in bytes) as the `BaseTraceEvent`. All new events _should_ be aligned by 4-byte boundaries.

The macro takes care of implementing required traits, adding an event type  (`etype`) field, and adding an event number field `event_num` if the **numbered** feature is enabled _(enabled by default)_.

```rust
#[styx_event(etype=TraceEventType::MEM_READ)]
struct MemReadEvent {
    pub size_bytes: u16,
    pub pc: u32,
    pub address: u32,
    pub value: u32,
}
```

For adding to the dispatch list, the `styx_event_dispatch` macro provides a mechanism that associates event types (`enum TraceEventType`) with specific event types, and enables polymorphic method calling, powered by [enum_dispatch](https://docs.rs/enum_dispatch/latest/enum_dispatch/).

To enable this mechanism, each new event is added to the `TraceableItem` enum. The macro takes care of creating the `enum_dispatch` variants.

```rust
#[styx_event_dispatch(BaseTraceEvent, Traceable)]
pub enum TraceableItem {
    InsnExecEvent(TraceEventType::INST_EXEC),
    InsnFetchEvent(TraceEventType::INST_FETCH),
    MemReadEvent(TraceEventType::MEM_READ),
    MemWriteEvent(TraceEventType::MEM_WRT),
    RegReadEvent(TraceEventType::REG_READ),
    RegWriteEvent(TraceEventType::REG_WRITE),
    BranchEvent(TraceEventType::BRANCH),
    ControlEvent(TraceEventType::CTRL),
    ...
}
```

## Viewing Events

When using the `strace!()` macro, events are viewable with the `strace` tool.

```bash
# from the repo root
cargo run --bin strace -- -help
```

The tool has 2 modes: "generate" for generating sample events, and "read" for reading events from a trace buffer.

With the `SharedRingBuffer` trace provider, events can be accessed via the memory mapped file in, for example:

```text
KFILE=/tmp/strace_150847_9edd2997-eada-4bcd-924d-74068705ddbb.srb
    #             ^      ^                                    ^
    #             |      |                                    +- file ext
    #             |      +- uuid4
    #             +- process id of emulator

strace -R -k $KEY_FILE -o text -v 3
```

## Performance Benchmarks

The table below shows performance stats for `cargo run --release -p benchmarks`.
For the _Action_ column the row labeled **PRODUCE** is the stats for emitting events, sequentially, using `strace!`.

The rows labeled **CONSUME**, **CAST**, **JSON**, and **TEXT** are variants of a client consuming events sequentially, where:

- CONSUME: is just the time to _read_ the event
- CAST: is the time to _read_ and _interpret_ the event (ie transmute or cast to a specific event type)
- JSON: is the time to _read_, _interpret_, and convert to `jsonl` using `serde::Serialize`
- TEXT: is the time to _read_, _interpret_, and convert to `text` using the derived `Debug` and rust's standard debug formatting.

Stats for 100 million _"numbered"_ events:

Action  | Time (rounded secs) | Rate (events/sec)
--------|---------------------|-----------
PRODUCE | 10                  |  9,454,832
CONSUME |  4                  | 20,710,341
CAST    |  5                  | 18,100,958
JSON    | 16                  |  5,999,676
TEXT    | 38                  |  2,604,706
