# Migration Guide

## 0.53.0 to 1.0.0

At a very high level, this refactor reorganized the major processor components and improved interactions between them.  See (TODO: add link to diagram) to get an idea of how components now fit together.  

A major paradigm shift was moving from `Arc<Mutex<>>` based components to `mut` components.  We realized that we were both spending a lot of time in locks and that most of these locks were not really necessary, so we changed it.  For users, this mostly affects Styx API calls in minor ways

Most of the changes that average users will encounter have to do with defining and building a processor.  This document gives examples of how code was structured before and after to help users migrate to the new release.

Other notable changes that users might encounter includes changes to import paths.

By and large it is encouraged to use prelude imports from styx_core::prelude::*or styx_emulator::prelude::*; when possible. Additionally many of the common modules that were used were elevated to more ergonomic positions in the import (notably styx_core::sync::sync is now just styx_core::sync).

Inside of `styx_core`, a lot has changed as we transition to a slightly different internal crate structure. This is leading to a partial sunsetting of styx-cpu retaining the majority of backend functionality and a reduced need for a large number of crates, consolidating a lot of the processor-level logic into `styx-processor`.

### Processor Definition

The previous way of defining a new processor involved lots of duplicated, boiler-plate code that could just be copy-pasted from an existing definition.  We realized that the `ProcessorImpl` was entirely stateless and pretty much only performed initialization duties.  We combined the previous `ProcessorImpl` and `BuildableProcessor` traits into a single, simplified trait and moved other behavior to different parts of the codebase.

#### Before

```rust
pub struct ExampleCpu {
    cpu: CpuBackend,
    #[derivative(Debug = "ignore")]
    event_controller: Arc<EvtController>,
    weak_ref: Weak<Self>,
}

impl BuildableProcessor for ExampleCpu {
    fn from_builder(
        variant: impl Into<styx_core::cpu::arch::backends::ArchVariant>,
        endian: styx_core::cpu::ArchEndian,
        exception_behavior: ExceptionBehavior,
        loader: Arc<dyn Loader>,
        target_program: Cow<[u8]>,
        runtime: Handle,
        backend: Option<Backend>,
    ) -> Result<Arc<Self>, ProcessorBuilderImplError> {
        ...
    }
}

impl ProcessorImpl for ExampleCpu {
    fn cpu(&self) -> CpuBackend {
        self.cpu.clone()
    }

    fn cpu_stop(&self) -> Result<(), StyxMachineError> {
        ...
    }

    fn event_controller(&self) -> Arc<dyn EventController> {
        self.event_controller.clone()
    }

    fn cpu_start(
        &self,
        timeout: Option<Duration>,
        insns: Option<u64>,
    ) -> Result<TargetExitReason, StyxMachineError> {
        ...
    }

    fn initialize(&self) -> Result<(), StyxMachineError> {
        ...
    }

    fn populate_default_registers(
        &self,
        desc: &mut MemoryLoaderDesc,
    ) -> Result<(), StyxMachineError> {
        ...
    }

    fn setup_address_space(&self) -> Result<(), StyxMachineError> {
        ...
    }
}
```

#### After

```rust
pub struct ExampleCpuBuilder {}

impl ProcessorImpl for ExampleCpuBuilder {
    fn build(
        &self,
        _runtime: &ProcessorRuntime,
        cpu_backend: Backend,
    ) -> Result<ProcessorBundle, UnknownError> {
        ...
    }

    fn init(&self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        ...
    }
}
```

See `styx/processors/arm/styx-kinetis21-processor/src/lib.rs` for an example of what implementing this trait looks like in practice.

### Instantiating a Processor

The previous `ProcessorBuilder` had options for things like endianness, architecture, architecture variants, and the build method was generic with the processor being built.  In the new architecture, most of these options are intrinsic to the processor being built and as such they are handled by the `ProcessorImpl` passed to `ProcessorBuilder::with_builder()`.

#### Before

```rust
    let proc = ProcessorBuilder::default()
        .with_endian(ArchEndian::LittleEndian)
        .with_executor(Executor::default())
        .with_loader(RawLoader)
        .with_target_program(get_firmware_path())
        .with_variant(ArmVariants::ArmCortexM3)
        .build::<ExampleCpu>()?;
```

#### After

```rust
    let mut proc = ProcessorBuilder::default()
        .with_builder(ExampleCpuBuilder {})
        .with_target_program(get_firmware_path())
        .build()?;
```

To run the processor use `Processor::run()` with an `ExecutionConstraint`. The simplest one is `Forever`.

```rust
let mut proc = ProcessorBuilder::default()
        .with_builder(ExampleCpuBuilder {})
        .with_target_program(get_firmware_path())
        .build()?;

proc.run(Forever);
```

### Hooks

The ways of adding and removing hooks haven't really changed but the hook callback function prototypes have changed.  Instead of a `CpuBackend` as the first argument to hook callbacks, you now get a `CoreHandle` which bundles together the cpu, mmu, and event controller components as mutable references.

#### Before

```rust
fn code_hook_callback(cpu: CpuBackend) {
    // do something
}
```

#### After

```rust
fn code_hook_callback(proc: CoreHandle) -> Result<(), UnknownError> {
    // do something
    Ok(())
}
```

### Memory Access

The 1.0 introduces the Mmu to the processor. This defined an api for device specific address translation. There is also support for separate code/data memory as is needed by some architectures. For the Styx user this means there is no longer `read_memory()`/`write_memory()` and instead `read_code()`/`write_code()` and `read_data()`/`write_data()` for code and data memory regions respectively. On architectures with no distinction between code/data memory then they will operate the same.

Data can be read without checking mmu permissions with the `sudo_` variants: e.g. `sudo_read_code()`.

There is also an experimental, alternative memory api accessed by the `Mmu::code()` and `Mmu::data()` methods. An example is shown below.

#### Before

```rust
fn code_hook_callback(cpu: CpuBackend) {
    let mut buf = [0u8; 4];
    cpu.read_memory(0x1000, &mut buf).unwrap();
    let my_u32 = u32::from_le_bytes(&buf);
}
```

#### After

```rust
fn code_hook_callback(proc: CoreHandle) -> Result<(), UnknownError> {
    let mut buf = vec![0u8; 8];
    cpu.read_data(0x1000, &mut buf)?; // read from data region
    let my_u32 = u32::from_le_bytes(&buf);

    // or with experiment memory api
    // note we can also use ? operator to propagate errors

    let my_u32 = cpu.data().read(0x1000).le().u32()?;

    Ok(())
}
```
