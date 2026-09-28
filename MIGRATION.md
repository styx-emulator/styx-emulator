# Migration Guide

## Multi-Processor Changes

`styx-processor` supports multiple vCPUs per processor. The change is broad and
mostly mechanical. It groups into three concerns:

1. [Multi-vCPU](#1-multi-vcpu): the processor core split, the `ProcessorBundle` builder, and the per-vCPU access pattern (`proc.vcpus[..]`).
2. [Event distributor](#2-event-distributor): the split of the event controller trait and the reshaped `Peripheral::tick`.
3. [Timing](#3-timing-delta-vs-globaldelta): the distinction between `Delta` and `GlobalDelta`.

### The core split

The old single `ProcessorCore`, which bundled cpu, mmu, and event controller, is
split in two:

| Type | Scope | Holds |
|---|---|---|
| `ProcessorCore` | processor-wide, shared between vCPUs | `Arc<MemoryBackend>`, `EventDistributor`, `ProcessorTime` |
| `VcpuCore` | per-vCPU | `Box<dyn CpuBackend>`, `Mmu`, secondary `EventController`, `VcpuTime` |

A `Processor` exposes `pub vcpus: Vec<VcpuCore>` and `pub core: ProcessorCore`.
Single-vCPU processors have one entry in `vcpus`.

## 1. Multi-vCPU

### Building a processor: `ProcessorBundle::builder()`

`ProcessorBundleBuilder` and the nested vCPU builders supply defaults for most
processor and vCPU components, and provide methods to add vCPUs.

```rust
// OLD
Ok(ProcessorBundle {
    cpu: Box::new(MyCpu),
    tlb: Box::new(MyTlb),
    event_controller: Box::new(MyEc),
    memory,
    peripherals,
    loader_hints,
})

// NEW: one vCPU, configured through the nested VcpuBundleBuilder
Ok(ProcessorBundle::builder()
    .with_memory(memory)
    .with_vcpu(|v| v.with_cpu(MyCpu).with_tlb(MyTlb).with_event_controller(MyEc))
    .add_peripheral(MyUart::new())
    .with_arch_hint(Arch::Arm)
    .build()?)

// NEW: 16 vCPUs configured quickly via `with_vcpus`
Ok(ProcessorBundle::builder()
    .with_memory(memory)
    .with_vcpus(16, |_idx, v| v.with_cpu(DummyBackend).with_event_controller(MyEc))
    .add_peripheral(MyUart::new())
    .with_arch_hint(Arch::Arm)
    .build()?)
```

See the `ProcessorBundleBuilder` docs for the full list of methods.

`modify_memory()` gives mutable access to the `MemoryBackend`, so memory can be
mapped from within the builder.

```rust
.with_memory(MemoryBackend::new_region_store())
.modify_memory(|mem| { mem.add_memory_region(/* .. */)?; Ok(()) })?
```

### Per-vCPU access in `init()` and elsewhere

`proc.core.cpu` and `proc.core.mmu` no longer exist. In `ProcessorImpl::init` and
other inits, `BuildingProcessor` exposes them through `vcpus`:

```rust
pub struct BuildingProcessor<'a> {
    pub vcpus: &'a mut [VcpuCore],   // NEW
    pub core: &'a mut ProcessorCore,
    pub runtime: &'a mut ProcessorRuntime,
    pub routes: RoutesBuilder,
    // ..
}
```

For processors that were previously single-vCPU, replace `proc.core.cpu` with
`proc.vcpus[0].cpu` and `proc.core.mmu` with `proc.vcpus[0].mmu`. Multi-vCPU
systems can add hooks to one or many vCPUs.

If your memory operations use physical addresses, `proc.memory()` gives a
reference to the `MemoryBackend`.

### Running processors: `Processor::run()` vs `Processor::run_multi()`

| Method | Returns | Notes |
|---|---|---|
| `proc.run(bounds)` | `EmulationReport` | errors if there is more than one vCPU |
| `proc.run_multi(bounds)` | `Vec<EmulationReport>` | one report per vCPU |

Single-vCPU callers are unaffected. Multi-vCPU callers must use `run_multi`.

### Other surface changes

- `CoreHandle::vcpu_id() -> VcpuId` identifies the current vCPU.
- `Processor::memory() -> &Arc<MemoryBackend>` returns shared physical memory.
- `Processor::for_vcpu(|v| ..)` and `Processor::add_hooks(|vcpu_id| StyxHook)` apply an operation or hook across every vCPU.

### Executor changes

The `ExecutorImpl` trait is gone, replaced by two traits behind an
`ExecutorKind`:

- `StrideExecutor`: the common case. The Styx core drives the multi-vCPU loop, so
  you supply only `get_stride_length()`, `halt_emulation() -> Option<HaltFn>`,
  and the `init`, `emulation_setup`, `emulation_teardown`, and `tick` lifecycle
  hooks.
- `CustomExecutor`: full control for debuggers and fuzzers. It has one method,
  `execute(&mut [VcpuCore], &mut ProcessorCore, &mut Plugins, &ExecutionConstraintConcrete) -> Result<Vec<EmulationReport>>`.
  A custom executor ticks all components itself.

Because the executor types are separate, `ProcessorBuilder` has different methods
depending on the executor type passed.

```rust
// when creating a processor
let builder = ProcessorBuilder::default();
// Stride executors keep `with_executor`.
// NOTE: the builder comes initialized with the default executor
// so you don't need to add the default executor, this is just
// for example purposes.
let builder = builder.with_executor(DefaultExecutor::default())
// GdbExecutor is a "custom executor"
let builder = builder.with_custom_executor(GdbExecutor::<Ppc4xxTargetDescription>::new(gdb_params)?)
// ExecutorKind can hold either custom or stride executors.
let builder = builder.with_executor_kind(ExecutorKind::custom(GdbExecutor::<Ppc4xxTargetDescription>::new(gdb_params)?));
```

## 2. Event distributor

The single `EventControllerImpl` trait is split into two.

| Trait | Scope | Role |
|---|---|---|
| `EventControllerImpl` (secondary) | per-vCPU | latch, next, and execute interrupts on its own CPU; also routes from the vCPU to the event distributor |
| `EventDistributorImpl` (primary) | processor-wide | owns peripherals and routes IRQs raised by peripheral ticks to the correct vCPU |

For single-vCPU processors the split requires little work: existing controller
logic stays as the secondary event controller, and the `SingleVcpuEventDistributor`
in the Styx core acts as the event distributor.

### Per-vCPU `EventControllerImpl`

Keep all latch, priority, and ISR logic. Only two signatures move:

- `next()` no longer takes `&mut Peripherals`, because peripherals moved to the event distributor.
- `tick()` gains a `&Delta` parameter.

`latch()`, `execute()`, `finish_interrupt()`, `reset()`, and `init()` are
unchanged. The dummy is still `DummyEventController`. `EventController::new()`
now takes `(Box<dyn EventControllerImpl>, vcpu_index: VcpuId)`, and
`finish_interrupt()` now returns `Option<ExceptionNumber>`.

### `EventDistributorImpl`

```rust
pub trait EventDistributorImpl {
    fn init(&mut self, vcpus: &mut [VcpuCore], memory: &Arc<MemoryBackend>) -> Result<(), UnknownError> { Ok(()) }
    fn on_processor_start(&mut self, vcpus: &mut [VcpuCore]) -> Result<(), UnknownError> { Ok(()) }
    fn on_processor_stop(&mut self, vcpus: &mut [VcpuCore]) -> Result<(), UnknownError> { Ok(()) }
    fn tick(&mut self, delta: &GlobalDelta, pending_irqs: &[ExceptionNumber], vcpus: &mut [VcpuCore]) -> Result<(), UnknownError> { Ok(()) }
    fn reset(&mut self, cpu: &mut dyn CpuBackend, mmu: &mut Mmu) -> Result<(), UnknownError> { Ok(()) }
    // latch(..), etc.
}
```

`SingleVcpuEventDistributor`, the default, routes every IRQ raised by a peripheral
tick to the secondary controller of `vcpus[0]`. Use it for single-vCPU processors
with interrupt-driven peripherals.

Write a custom `EventDistributorImpl` when you have processor-wide lifecycle or
routing logic, such as routing IRQs to one specific core.

### `Peripheral::tick` has a new signature and returns IRQs

The event distributor owns peripherals. It ticks each one per round, collects the
returned IRQs, and hands them to `EventDistributorImpl::tick` for routing.

```rust
// OLD: latched directly onto the event controller
fn tick(&mut self, cpu: &mut dyn CpuBackend, mmu: &mut Mmu,
        ec: &mut dyn EventControllerImpl, delta: &Delta) -> Result<(), UnknownError> {
    if self.has_data() { ec.latch(self.irqn)?; }
    Ok(())
}

// NEW: returns the IRQs it wants raised
fn tick(&mut self, ctx: &PeripheralTickCtx<'_>) -> Result<RaisedIrqs, UnknownError> {
    let mut raised = RaisedIrqs::none();
    if self.has_data() { raised.push(self.irqn); }
    Ok(raised)
}
```

What `tick` can and cannot do:

- Can: read `ctx.delta`, and read and write physical memory through `ctx.memory`
  (`&MemoryBackend`). DMA-style peripherals can write guest memory directly
  instead of staging through an MMIO hook.
- Cannot: touch CPU registers, touch a per-vCPU MMU or virtual address, or call
  `latch` directly. Register a hook in `init()` if you need register or virtual
  memory access.

### Peripheral hooks

Peripherals no longer live near vCPUs, so hooks no longer have access to the
peripheral that owns them (previously via
`proc.event_controller.peripherals.get_expect::<MyPeripheral>()?;`).

Share peripheral data with hooks through an `Arc`ed data store. The stm32f107
processor's i2c implementation is an example.

```rust
// in Peripheral::init
cpu.add_hook(StyxHook::memory_write(
    base_addr + I2C_CR1_OFFSET,
    hooks::I2cCr1WHook { inner: i2c.clone() },
))?;

pub(crate) struct I2cCr1WHook {
    pub(crate) inner: Arc<Mutex<I2CPortInner>>,
}

impl MemoryWriteHook for I2cCr1WHook {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        _size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        let port = self.inner.lock().unwrap();
        // do some stuff with `port`
        Ok(())
    }
}
```

### Migrate away from `post_event_hook`

`post_event_hook`, and any related "peripheral event done" callbacks, is removed
from the `Peripheral` trait and from its UART and SPI implementations. The
callback fired on the peripheral that raised an interrupt once the firmware
returned from the handler, letting the peripheral do post-event cleanup such as
re-latching an IRQ that still had data pending. Detecting return from interrupt
is architecture specific and fragile, and some firmware never returns from the
handler at all (FreeRTOS on PPC, for example), so the mechanism was dropped. The
[Remove Post Event Hook ADR](docs/source/adrs/3-remove-post-event-hook.rst) has
the full rationale.

If your peripheral relied on `post_event_hook` to re-check state, move that logic
into `Peripheral::tick`. It runs every round and returns the IRQs to raise, so
re-latching happens on the next tick without a dedicated callback.

## 3. Timing: `Delta` vs `GlobalDelta`

The split introduces two delta types, one for processor time and one for vCPU
time.

| Type | Fields | Used by |
|---|---|---|
| `Delta` (per-vCPU, per-stride) | `count: u64`, `time: Duration` | secondary `EventControllerImpl::tick`, `post_stride_processing`, `HaltFn` |
| `GlobalDelta` (system-level, per-round) | `simulated_time: u64`, `wall_time: Duration` | `Peripheral::tick` (`ctx.delta`), `EventDistributorImpl::tick`, `Plugin::tick` |

`ProcessorCore::time` (`ProcessorTime`) tracks the processor-wide simulated
clock and advances once per round. `VcpuCore::time` (`VcpuTime`) tracks per-vCPU
time. See the `styx_core::executor::time` module docs for the full model.

## 1.0.0 to 1.2.0

### Emulation API Changes

The API for `Executor`, `CpuBackend` and `Processor` emulation has been updated to provide more detailed execution information. The return type for emulation methods has changed from `Result<TargetExitReason, ...>` to `Result<EmulationReport, ...>`.

#### Before

```rust
let exit_reason: TargetExitReason = processor.run(constraint)?;
// exit_reason is a TargetExitReason enum
```

#### After

```rust
let report: EmulationReport = processor.run(constraint)?;
// report is an EmulationReport containing:
// - exit_reason: TargetExitReason
// - instruction_count: u64
// - etc.
```

This change allows users to access additional execution information like instruction counts and other metrics without requiring separate API calls.

**NOTE**: this also propagated to the python and C bindings accordingly

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
