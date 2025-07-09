// SPDX-License-Identifier: BSD-2-Clause
//! The [`Gpio`] provides an interface between the event manager and the individual
//! GPIO ports. It provides little more than a container with minimal
//! orchestration.
//!
//! Structure layout:
//!                                                 ┌──────────┐
//!                                    ┌───────────►│ Register │
//!                                    │            └──────────┘
//!                                    │
//!                                    │            ┌──────────┐
//!                                    ├───────────►│ Register │
//!                                    │            └──────────┘
//!                                    │                 .
//!                                    │                 .
//!                                    │                 .
//! ┌────────┐                         │            ┌──────────┐
//! │        │       ┌──────────┐      ├───────────►│ Register │
//! │  Gpio  ├──┬───►│ GPIOPort ├──────┤            └──────────┘
//! │        │  │    └──────────┘      │
//! └────────┘  │                      │
//!             │    ┌──────────┐      │
//!             ├───►│ GPIOPort │      │            ┌──────┐
//!             │    └──────────┘      ├───────────►│ Pin  │
//!             │         .            │            └──────┘
//!             │         .            │
//!             │         .            │            ┌──────┐
//!             │         .            ├───────────►│ Pin  │
//!             │    ┌──────────┐      │            └──────┘
//!             └───►│ GPIOPort │      │               .
//!                  └──────────┘      │               .
//!                                    │               .
//!                                    │            ┌──────┐
//!                                    └───────────►│ Pin  │
//!                                                 └──────┘
//!
use styx_core::prelude::*;
use tracing::trace;

mod constants;
mod pin;
mod port;

use constants::{GPIO_BASE, GPIO_END, GPIO_PORTS};
use port::GPIOPort;

/// Notional example of a GPIO peripheral for `kinetis_21`.
pub struct Gpio {
    /// A vector of all the GPIO ports in the system.
    ports: Vec<GPIOPort>,
    base: u64,
    end: u64,
}

impl Default for Gpio {
    fn default() -> Self {
        trace!("Initialize the GPIO");
        let mut ports: Vec<GPIOPort> = Vec::new();
        for (port_name, port_map) in GPIO_PORTS {
            let port = GPIOPort::new(port_name, &port_map);
            ports.push(port);
        }

        Self {
            ports,
            base: GPIO_BASE,
            end: GPIO_END,
        }
    }
}

impl Peripheral for Gpio {
    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        // We choose to hook the memory region for the entire GPIO so we can maintain two hooks
        // (one read and one write) instead of two per GPIO port (which would result in 10 hooks in
        // this case).
        trace!("GPIO .register_hooks()");
        trace!("Set GPIO read and write hooks at {:#8x}", self.base);

        proc.core
            .cpu
            .mem_write_hook(self.base, self.end, Box::new(gpio_write_callback))?;
        proc.core
            .cpu
            .mem_read_hook(self.base, self.end, Box::new(gpio_read_callback))?;

        Ok(())
    }

    fn reset(&mut self, _cpu: &mut dyn CpuBackend, mmu: &mut Mmu) -> Result<(), UnknownError> {
        trace!("GPIO .reset_state()");
        for port in self.ports.iter_mut() {
            port.reset_state(mmu)?;
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "GPIO"
    }
}

/// Callback function for writes to GPIO memory-mapped registers.
///
/// Based on the address, find the corresponding port and call its instance's `mem_write_callback`
/// function.
pub fn gpio_write_callback(
    proc: CoreHandle, // Emulator
    address: u64,     // Accessed Address
    size: u32,        // Number of bytes accessed
    value: &[u8],     // Write Value
) -> Result<(), UnknownError> {
    let gpio = proc.event_controller.peripherals.get::<Gpio>().unwrap();

    // TODO: need to <T> - pretty much hard-coded to u32
    assert!(size == 4, "We assume 4-byte GPIO writes.");

    for port in gpio.ports.iter_mut() {
        if port.addr_range.contains(&address) {
            port.mem_write_callback(address, size, value);
        }
    }

    Ok(())
}

/// Callback function for reads of GPIO memory-mapped registers.
///
/// Based on the address, find the corresponding port and call its instance's `mem_read_callback`
/// function.
pub fn gpio_read_callback(
    proc: CoreHandle, // Emulator
    address: u64,     // Accessed Address
    size: u32,        // Number of bytes accessed
    value: &mut [u8], // Read Value
) -> Result<(), UnknownError> {
    let gpio = proc.event_controller.peripherals.get::<Gpio>().unwrap();

    // TODO: need to <T> - pretty much hard-coded to u32
    assert!(size == 4, "We assume 4-byte GPIO reads.");

    for port in gpio.ports.iter_mut() {
        if port.addr_range.contains(&address) {
            port.mem_read_callback(proc.mmu, address, size, value);
        }
    }

    Ok(())
}
