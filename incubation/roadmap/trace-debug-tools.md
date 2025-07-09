# Styx Execution Trace Tools Roadmap

Summary, for roadmap context. *(details at
[`trace-tools/README.md`](../../../incubation/trace-tools/README.md))*

- ptrace: cli for running emulations and trace analysis
- webapp: typescript/Angular web application that uses service `TraceAppSessionService`
- `TraceAppSessionService`: primary service for the webapp
- `EmulationRegistryService`: keeps track of `SingleEmulationService` instances
- `SingleEmulationService`: runs a single styx emulation
- `Typhunix`: provides interop with Ghidra for `Programs`, `Symbols`, `DataTypes`, etc
- `trace-tools`: crate that provides heavy lifting (rename to trace-tools-lib`)

*(services are a thin - implementation is in the
`trace-tools-lib` crate which sits atop **styx-core**.)*

## Roadmap

## Functional Requirements

From an application / styx-frontend perspective, what use cases / users stories do we want to support?

- [ ] Webapp: fleshout use cases / user stores (what functionality do we want to see?)
- [ ] ptrace: fleshout use cases / user stores (what functionality do we want to see?)

### Integration Testing Examples

- [ ] Add one or more sample ghidra projects so that the full stack of tools can be integration tested with a full compliment of ghidra symbols

### LDM and Database

Implementation of many features is simplified by a well-defined logical domain model.
For database, prefer a skeletal *(vs strict/BCNF)* schema with `json` or `jsonb` blobs for a higher velocity
develop/break/fix cycle. Postgres is very good at `JSON`, all the `gRPC`
messages are json-serializable.

- `Program`, `Symbol`, `DataType`, `Architecture`, `Cpu`, `Processor`, ...,  etc.
- this is *logical*, but with close correlation to `idl/` / `proto/`
- a fair amount of this exists in documentation, some is informed by the `idl/proto`

- [ ] Flesh out out an object domain model: all of the key entities and relationships.
- [ ] Add a postgres database (`LDM` before full-blown implementation)

### ptrace

- [ ] integrate workspaces
- [ ] improve text visualizations

### Webapp

- [ ] Add/remove/list `ProgramBinary` *(the thing formerly known as firmware)*
- [ ] Select analysis from supported list
- [ ] integrate workspaces
- [ ] define / improve / expand graphical visualizations
- [ ] Fix/expand unit and integration tests
- [ ] Control emulation: launch, stop, start (executor behavior)
- [ ] ProgrmBinaryService (add, remove, list)
- [ ] Associate ProgramBinary with `symbolic.Program`

### Workspace

- [ ] Conceptualize workspaces.

- unite program, target/variant, program-bin-path, ...

A workspace is an that associates and encapsulates a `symbolic.Program` and all
its symbols and datatypes, one or more `BinaryProgram`s, a `Target`, etc.

- fine-grained options for emulation and tracing
- ...

The workspace can establish/launch:

- a running Ghidra instance
- a running emulation or trace session
- interop between ghidra and styx using `typhunix`

How does it work?

- for a linux cli, it could have the feel of
[virtualenvrapper]([Stm32f107](https://virtualenvwrapper.readthedocs.io/en/latest/)),
with shell functions to:

- manage workspaces: create,list,remove,copy,...
- run things: emulation, ghidra, trace sessiones, etc

### proto / idl

- [ ] Move proto to idl
- [ ] organize functionally

### `styx-trace`

- [ ] Rollover styx-trace output files
- [ ] Control events so that trace files do not need context (memory region sizes, etc)
