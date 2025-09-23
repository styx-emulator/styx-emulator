// SPDX-License-Identifier: BSD-2-Clause
use styx_core::errors::UnknownError;
use tokio::runtime::Handle;

use crate::{
    components::{Component, ComponentStore, DuplicateId},
    processor::Processors,
};

/// Uart peripheral service.
mod uart;

/// A proxy service implementation.
///
/// Strictly speaking this is a function that *spawns* the proxy service on
/// the provided async runtime. Peripheral services should error on an invalid
/// config schema, invalid config values, or if a processor cannot be connected.
///
/// Use [`ProcessorId`](crate::config::ProcessorId) and [`Processors`] to find and connect to processors.
pub type ProxyService = fn(
    config: Option<&serde_yaml::Value>,
    processors: &Processors,
    runtime: &Handle,
) -> Result<ProxyHandle, UnknownError>;

inventory::collect!(Component<ProxyService>);

/// Handle to introspect a running peripheral proxy.
///
/// Use [`peripheral_service_handle()`] to create.
///
/// does nothing at the moment but planning to use in the future to start/stop services and edit configs
pub struct ProxyHandle {}
/// Service side of the handle to introspect a running peripheral proxy.
///
/// Use [`peripheral_service_handle()`] to create.
///
/// does nothing at the moment but planning to use in the future to start/stop services and edit configs
pub struct ProxyHandleController {}

/// Create a handler pair, called by a proxy service.
pub(crate) fn peripheral_service_handle() -> (ProxyHandleController, ProxyHandle) {
    (ProxyHandleController {}, ProxyHandle {})
}

/// Get a populated [`ComponentStore`] of [`ProxyService`]s register via inventory.
///
/// Can error if multiple proxy services have the same id.
pub fn registered_peripherals() -> Result<ComponentStore<ProxyService>, DuplicateId> {
    ComponentStore::populated()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify UART is available in the peripheral service list.
    #[test]
    fn test_uart_available() {
        let peripherals = registered_peripherals().unwrap();
        assert!(peripherals.list().any(|i| i == "uart"));
    }
}
