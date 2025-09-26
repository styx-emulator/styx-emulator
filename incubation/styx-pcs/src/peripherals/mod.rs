use styx_core::errors::UnknownError;
use tokio::runtime::Handle;

use crate::{
    components::{Component, ComponentStore, DuplicateId},
    processor::Processors,
};

/// Uart peripheral service.
mod uart;

/// A peripheral service implementation.
///
/// Strictly speaking this is a function that *spawns* the peripheral service on
/// the provided async runtime. Peripheral services should error on an invalid
/// config schema, invalid config values, or if a processor cannot be connected.
///
/// Use [`ProcessorId`](crate::config::ProcessorId) and [`Processors`] to find and connect to processors.
///
pub type PeripheralService = fn(
    config: Option<&serde_yaml::Value>,
    processors: &Processors,
    runtime: &Handle,
) -> Result<PeripheralServiceHandle, UnknownError>;

inventory::collect!(Component<PeripheralService>);

/// Handle to introspect a running peripheral service.
///
/// Use [`peripheral_service_handle`] to create.
///
/// TODO: does nothing at the moment but planning to use in the future to start/stop services.
pub struct PeripheralServiceHandle {}
/// Handle to introspect a running peripheral service.
///
/// Use [`peripheral_service_handle`] to create.
///
/// TODO: does nothing at the moment but planning to use in the future to start/stop services.
pub struct PeripheralServiceHandler {}
pub fn peripheral_service_handle() -> (PeripheralServiceHandler, PeripheralServiceHandle) {
    (PeripheralServiceHandler {}, PeripheralServiceHandle {})
}

pub fn peripherals() -> Result<ComponentStore<PeripheralService>, DuplicateId> {
    ComponentStore::populated()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify UART is available in the peripheral service list.
    #[test]
    fn test_uart_available() {
        let peripherals = peripherals().unwrap();
        assert!(peripherals.list().any(|i| i == "uart"));
    }
}
