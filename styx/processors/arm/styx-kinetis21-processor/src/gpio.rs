// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
