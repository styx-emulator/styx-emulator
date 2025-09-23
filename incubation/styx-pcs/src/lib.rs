// SPDX-License-Identifier: BSD-2-Clause
//! Styx Peripheral Communication Service
//!
//! The Peripheral Communication Service (PCS) enabled multiple gRPC servers (processors) to communicate
//! with each other by spawning proxies to communicate.
//!
//! Additional proxy services can be implemented by registering a new [`ProxyService`].
//!
//! Start the PCS using [`start_pcs()`].
//!
//! ## Components
//!
//! Components are a concept borrowed from styx-uconf.
//! Basically, a component is a const object (usually a function pointer) that is collected via inventory.
//! Collection via inventory means that any crate being compiled can register a component.
//! All registered components are collected by the crate that defined the component type.
//!
//! ## Proxy Service
//!
//! styx-pcs defines the [`ProxyService`] component.
//! A Proxy service proxies traffic between several processors (gRPC servers) over a
//! peripheral protocol (e.g. uart, spit, i2c, etc.).
//!
//! This crate currently defines a `uart` proxy service.
//! Users can define their own by defining a function with the [`ProxyService`] signature and calling
//! [`inventory::submit!()`] on the component instantiated using [`component!()`].
//!
//! ## Unimplemented
//!
//! - Spawn clients from styx-devices
//!   - This is present in the config but not implemented yet
//!

/// Component logic for register peripheral implementations.
pub mod components;
use components::ComponentReference;

/// Configuration of the PCS, should be deserializable.
mod config;
pub use config::*;

/// Included peripheral implmentations.
mod peripherals;
pub use peripherals::*;

/// Processors that can be configured to connect to.
mod processor;
pub use processor::*;

use styx_core::prelude::*;
use tokio::runtime::Handle;

/// Spawns the Peripheral Component Service on the given runtime
pub fn start_pcs(config: &PcsConfig, runtime: &Handle) -> Result<(), UnknownError> {
    // TODO we should spawn local devices below
    // create a list of remote devices (processors/gRPC servers) and a list of local devices
    let (remote_devices, _spawn_devices) = config.devices.separate();
    let processors = Processors::from_config(remote_devices)?;
    let peripherals =
        peripherals::registered_peripherals().context("could not collect peripherals")?;

    // spawn proxies
    for proxy in config.connections.iter() {
        let component_ref = &proxy.component_ref;
        // call to spawn a new proxy
        let proxy_generator = peripherals.get(component_ref.id())?;
        log::info!("spawning proxy for {}", component_ref.id());
        // spawn peripheral proxy service, don't use handle for now
        // in the future we can use the handle to edit the config during runtime and monitor the service
        let _handle = proxy_generator(
            component_ref.config().map(|c| &c.config),
            &processors,
            runtime,
        )
        .with_context(|| {
            format!(
                "could not spawn peripheral proxy service `{}`",
                component_ref.id()
            )
        })?;
    }

    Ok(())
}
