# Styx Execution Trace Tools

*fsink* - Utility program that watches the trace directory looking for new `*.srb` files. For each one, it will open and process events, saving the results as a raw trace file.

*ptrace* - command-line tool for running trace executions

*strace* - command line utility for viewing raw events

*traceapp* - client app for the traceapp-service gRPC service

*traceapp-service* - the `TraceAppSessionService` gRPC service implmentation. Also contains a `main` for launching the service.

## ptrace tool

raw:

  provide trace analysis of raw file
  srb          Trace an SRB file
  launch       Start an emulation target (no analysis)
  emulate-min  Emulate a target using just typhunix
  emulate      Emulate a target using full web stack
  from-yaml    Gather emulation args from the YAML file
  post         post trace analysis
  help         Print this message or the help of the given subcommand(s)

## EmuObserver

`EmuObserver`

## Streams

- stream type: futures_core::Stream
- use async_stream::stream;
- use futures_util::pin_mut;
- use futures_util::stream::StreamExt;

### AggregateEvent Emitters

#### Read from raw files

```rust
pub fn event_stream_from_raw<'a>(
        &'a self,
        filename: &str,
    ) -> Result<impl Stream<Item = AggregateEvent> + 'a, Status> {
```

#### Read from SRB files

```rust
events_stream_from_srb<'a>(
        &'a self,
        keyfile: &str,
        timeout: Duration,
    ) -> Result<impl Stream<Item = AggregateEvent> + 'a, tonic::Status>;
```

#### Event Repeater

```rust
pub async fn events<'a>(
        &'a self,
        erx: &'a mut Receiver<StartTraceAppSessionResponse>,
    ) -> Result<impl futures_core::Stream<Item = styx_trace_tools::event::AggregateEvent> + 'a, Status>
```

### AggregateEvent Consumers

#### webapp session

```rust
async fn process_aggregate_events(
        &self,
        input_stream: impl Stream<Item = AggregateEvent>,
        output_stream: Sender<Result<StartTraceAppSessionResponse, Status>>,
        request: InitializeTraceRequest,
    ) -> Result<StreamEndReason, Status>
```


#### text base analyzers

```rust
async fn at_stats(
    options: &impl HasAnalysisOptions,
    cancel_token: CancellationToken,
    stream: &mut (impl Stream<Item = AggregateEvent> + std::marker::Unpin)
)
```
