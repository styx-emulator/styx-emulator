# Styx Component Templates Quick Start

This guide will walk you through creating your first Styx component using cargo-generate templates.

## Installation

```bash
# Install cargo-generate if you haven't already
cargo install cargo-generate --locked
```

## Creating Your First Component

### 1. Choose Your Component Type

Decide what type of component you need:

- **Processor**: Full microcontroller/SoC implementation
- **Event Controller**: Interrupt controller
- **Peripheral**: Hardware device (UART, SPI, timer, etc.)
- **Plugin**: Modular processor extension

### 2. Generate the Component

From the Styx repository root:

```bash
cargo generate --path styx/templates
```

Answer the prompts:

```text
? What type of component are you creating? peripheral
? Is this an in-tree component (part of the Styx workspace)? true
? What is the name of your component? my-timer
? Brief description of your component: A simple timer peripheral
```

### 3. Locate Your New Component

The generator creates a new crate. Move it to the appropriate location:

```bash
# For a peripheral
mv styx-my-timer styx/peripherals/

# For a processor
mv styx-my-timer-processor styx/processors/<arch>/

# For an event controller
mv styx-my-timer styx/event-controllers/<arch>/

# For a plugin
mv styx-my-timer styx/plugins/
```

### 4. Add to Workspace

Edit the root `Cargo.toml` to include your component:

```toml
[workspace]
members = [
    # ... existing members
    "styx/peripherals/styx-my-timer",
]
```

### 5. Implement Your Component

Open `src/lib.rs` and look for `TODO` comments:

```rust
// Example for a peripheral
impl Peripheral for MyTimer {
    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        // TODO: Register memory hooks for peripheral registers
        // Register a hook for the timer control register at 0x4000_0000
        proc.core.cpu.add_hook(StyxHook::memory_write(
            0x4000_0000,
            |handle, addr, size, value| {
                // Handle writes to control register
                Ok(())
            }
        ))?;

        Ok(())
    }

    fn tick(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        event_controller: &mut dyn EventControllerImpl,
        delta: &Delta,
    ) -> Result<(), UnknownError> {
        // Update timer state based on elapsed time/instructions
        self.counter += delta.instructions;

        // Trigger interrupt if timer expired
        if self.counter >= self.target {
            event_controller.latch(self.irq_number)?;
        }

        Ok(())
    }

    // Implement other required methods...
}
```

### 6. Build and Test

```bash
# Build your component
cargo build -p styx-my-timer

# Run tests
cargo test -p styx-my-timer

# Build entire workspace
cargo build
```

## Component Lifecycle

If you are creating a component for the first time, it might get a little overwhelming
on where and what to start with. Styx is a interconnected set of interfaces that allow
you to do almost anything you want. But it's still difficult to get a hang of where
your code and hooks actually get executed.

The following lifecycle notes should help you get situated for faster prototyping of your
custom components. Please reach out if you encounter any roadblocks or difficulty with
anything.

### Processor Lifecycle

```text
ProcessorBuilder::with_builder(MyProcessorBuilder)
    └─> ProcessorImpl::build()  [Create CPU, MMU, EventController, Peripherals]
        └─> ProcessorImpl::init()  [Initialize registers, hooks, state]
            └─> Processor ready for execution
```

### Event Controller Lifecycle

```text
EventController::init()
    └─> EventController::latch(irq)  [Queue interrupt]
        └─> EventController::next()  [Select and execute interrupt]
            └─> EventController::finish_interrupt()  [Cleanup]
```

### Peripheral Lifecycle

```text
Peripheral::init()  [Register hooks, setup state]
    └─> on_processor_start()  [Startup behavior]
        └─> tick()  [Periodic updates during execution]
            └─> post_event_hook()  [Handle interrupt completion]
                └─> on_processor_stop()  [Cleanup]
```

### Plugin Lifecycle

```text
UninitPlugin::init()  [Initialize, register hooks]
    └─> Plugin::plugins_initialized_hook()  [Cross-plugin setup]
        └─> Plugin::on_processor_start()
            └─> Plugin::tick()  [Runtime behavior]
                └─> Plugin::on_processor_stop()
```

## Common Patterns

Here are some common patterns that connect the hardware to the actual code
being executed.

### Registering Memory Hooks

```rust
// Read hook
proc.core.cpu.add_hook(StyxHook::memory_read(
    address,
    |handle, addr, size| {
        let value = /* compute value */;
        handle.mmu.data().write(addr).bytes(&value)?;
        Ok(())
    }
))?;

// Write hook
proc.core.cpu.add_hook(StyxHook::memory_write(
    address,
    |handle, addr, size, value| {
        // Process the written value
        Ok(())
    }
))?;
```

### Triggering Interrupts

```rust
// From a peripheral's tick() method
impl Peripheral for MyPeripheral {
    fn tick(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        event_controller: &mut dyn EventControllerImpl,
        delta: &Delta,
    ) -> Result<(), UnknownError> {
        if self.should_interrupt() {
            // This latch tells the EventController to "insert" an
            // interrupt. The target specific priorities and interrupt
            // maskss will determine when it is actually executed.
            event_controller.latch(self.irq_number)?;
        }
        Ok(())
    }
}
```

### Accessing Memory

```rust
// Read from memory
let value: u32 = handle.mmu.data().read(address).u32()?;

// Write to memory
handle.mmu.data().write(address).u32(0x1234_5678)?;
```

### Running Validation Locally

You can test the templates locally using the provided script:

```bash
# From repository root
./styx/templates/scripts/test-templates-local.sh
```

This script will:

- Generate all template types in `/tmp/styx-template-tests-<timestamp>`
- Build each component
- Verify trait implementations

## Other in-tree examples

- **Simple Peripheral**: `styx/peripherals/styx-uart/src/lib.rs`
- **Complex Processor**: `styx/processors/ppc/styx-ppc4xx-processor/src/lib.rs`
- **Event Controller**: `styx/event-controllers/arm/styx-nvic/src/lib.rs`
- **Plugin**: `styx/plugins/styx-gdbserver/src/lib.rs`
