# {{crate_name}}

{{component_description}}

## Overview

{% if component_type == "processor" %}This is a processor implementation for {{component_name}}. It provides the `ProcessorImpl` trait implementation required to create a fully functional Styx processor.

## Architecture

- **CPU Backend**: Configurable (Pcode, Unicorn)
- **Architecture**: TODO - specify architecture (ARM, x86, RISC-V, etc.)
- **Endianness**: TODO - specify endianness

## Memory Map

TODO: Document your processor's memory layout

Example:

| Region | Base Address | Size | Permissions | Description |
|--------|--------------|------|-------------|-------------|
| Flash  | 0x0800_0000  | 1MB  | RWX         | Program flash |
| SRAM   | 0x2000_0000  | 128KB| RWX         | Main RAM |
| Peripherals | 0x4000_0000 | 512MB | RW     | Memory-mapped peripherals |

## Usage

```rust
use styx_core::prelude::*;
use {{crate_name}}::{{struct_name_builder}};

let processor = ProcessorBuilder::default()
    .with_builder({{struct_name_builder}}::default())
    .build()?;

// Run the processor
processor.run(1000)?;  // Run for 1000 instructions
```

## Features

- TODO: List implemented features
- TODO: Note any deviations from hardware
- TODO: Document known limitations

{% elsif component_type == "event-controller" %}This is an event controller implementation for {{component_name}}. It manages interrupt handling and peripheral coordination.

## Supported Interrupts

TODO: Document the interrupt numbers and priorities your controller supports

Example:

| Exception # | Name | Priority | Description |
|-------------|------|----------|-------------|
| 1 | Reset | -3 (highest) | Reset handler |
| 2 | NMI | -2 | Non-maskable interrupt |
| 16+ | IRQ0+ | Configurable | External interrupts |

## Usage

```rust
use styx_core::prelude::*;
use {{crate_name}}::{{struct_name}};

// Event controller is typically used within a ProcessorImpl
let event_controller = Box::new({{struct_name}}::new());

// Or access from a built processor
let mut proc = /* ... */;
let controller = proc.core.event_controller.get_impl::<{{struct_name}}>()?;
```

## Interrupt Handling

TODO: Document your interrupt handling model

- Priority scheme
- Preemption rules
- Nesting behavior

{% elsif component_type == "peripheral" %}This is a peripheral implementation for {{component_name}}.

## Register Map

TODO: Document memory-mapped registers

Example:

| Offset | Register | Access | Description |
|--------|----------|--------|-------------|
| 0x00 | CTRL | RW | Control register |
| 0x04 | STATUS | RO | Status register |
| 0x08 | DATA | RW | Data register |

## Interrupts

TODO: Document interrupt behavior

- IRQ numbers
- Trigger conditions
- Clearing mechanism

## Usage

```rust
use styx_core::prelude::*;
use {{crate_name}}::{{struct_name}};

// Add to processor during build
let peripheral = Box::new({{struct_name}}::new());

// In ProcessorImpl::build():
let peripherals: Vec<Box<dyn Peripheral>> = vec![
    Box::new({{struct_name}}::new()),
];
```

## External Interface

TODO: If this peripheral has external I/O (UART, SPI, etc.), document the interface

{% elsif component_type == "plugin" %}This is a plugin for {{component_name}}. Plugins provide modular, reusable functionality that extends processor capabilities.

## Features

TODO: List what this plugin provides

- What hooks does it register?
- What behavior does it modify?
- What data does it collect/output?

## Usage

```rust
use styx_core::prelude::*;
use {{crate_name}}::{{struct_name}};

let processor = ProcessorBuilder::default()
    .add_plugin({{struct_name}}::new())
    .with_builder(/* processor builder */)
    .build()?;
```

## Configuration

TODO: Document configuration options

```rust
let plugin = {{struct_name}}::new()
    .with_enabled(true);
    // Add more builder methods as needed
```

{% endif %}

## Implementation Status

- [ ] Basic structure
- [ ] Core functionality
- [ ] Error handling
- [ ] Tests
- [ ] Documentation
- [ ] Examples

## Testing

```bash
# Run tests
cargo test

# Run with logging
RUST_LOG=trace cargo test -- --nocapture
```

## Dependencies

See `Cargo.toml` for full dependency list. Key dependencies:

- `styx-core`: Core Styx types and traits
- `thiserror`: Error handling
- `tracing`: Logging and diagnostics

## References

TODO: Add links to:

- Hardware datasheets
- Technical reference manuals
- Related documentation

## License

BSD-2-Clause
