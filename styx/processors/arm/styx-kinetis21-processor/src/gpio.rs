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
use std::sync::{Arc, Mutex};
use styx_core::hooks::{MemoryReadHook, MemoryWriteHook};
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
    ///
    /// Shared with the memory-mapped register hooks via this handle.
    ports: Arc<Mutex<Vec<GPIOPort>>>,
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
            ports: Arc::new(Mutex::new(ports)),
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

        proc.vcpus[0].cpu.mem_write_hook(
            self.base,
            self.end,
            Box::new(GpioWriteHook {
                ports: self.ports.clone(),
            }),
        )?;
        proc.vcpus[0].cpu.mem_read_hook(
            self.base,
            self.end,
            Box::new(GpioReadHook {
                ports: self.ports.clone(),
            }),
        )?;

        Ok(())
    }

    fn reset(&mut self, mmu: &mut Mmu) -> Result<(), UnknownError> {
        trace!("GPIO .reset_state()");
        for port in self.ports.lock().unwrap().iter_mut() {
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
struct GpioWriteHook {
    ports: Arc<Mutex<Vec<GPIOPort>>>,
}

impl MemoryWriteHook for GpioWriteHook {
    fn call(
        &mut self,
        _proc: CoreHandle,
        address: u64,
        size: u32,
        value: &[u8],
    ) -> Result<(), UnknownError> {
        // TODO: need to <T> - pretty much hard-coded to u32
        assert!(size == 4, "We assume 4-byte GPIO writes.");

        for port in self.ports.lock().unwrap().iter_mut() {
            if port.addr_range.contains(&address) {
                port.mem_write_callback(address, size, value);
            }
        }

        Ok(())
    }
}

/// Callback function for reads of GPIO memory-mapped registers.
///
/// Based on the address, find the corresponding port and call its instance's `mem_read_callback`
/// function.
struct GpioReadHook {
    ports: Arc<Mutex<Vec<GPIOPort>>>,
}

impl MemoryReadHook for GpioReadHook {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        value: &mut [u8],
    ) -> Result<(), UnknownError> {
        // TODO: need to <T> - pretty much hard-coded to u32
        assert!(size == 4, "We assume 4-byte GPIO reads.");

        for port in self.ports.lock().unwrap().iter_mut() {
            if port.addr_range.contains(&address) {
                port.mem_read_callback(proc.mmu, address, size, value);
            }
        }

        Ok(())
    }
}
