/// Component logic for register peripheral implementations.
mod components;
/// Configuration of the PCS, should be derserializable.
mod config;
/// Deserializable config for PCS. mod config;
/// Included peripheral implmentations.
mod peripherals;
/// Processors to connect to.
mod processor;

use components::config::ComponentReference;
pub use config::PcsConfig;

use processor::Processors;
use styx_core::prelude::*;
use tokio::runtime::Handle;

pub type Spawnable = ();

/// Starts the Peripheral Component Service on the given runtime
pub fn start_pcs(config: PcsConfig, runtime: &Handle) -> Result<(), UnknownError> {
    // TODO spawn devices
    let (remote_devices, _spawn_devices) = config.devices.separate();
    let processors = Processors::from_config(&remote_devices)?;
    let peripherals = peripherals::peripherals().context("could not collect peripherals")?;

    for connection in config.connections.iter() {
        let component_ref = &connection.component_ref;
        let generator = peripherals.get(component_ref.id())?;
        log::info!("spawning proxy generator for {}", component_ref.id());
        // spawn peripheral proxy service, don't use handle for now
        let _handle = generator(
            component_ref.config().map(|c| &c.config),
            &processors,
            runtime,
        )
        .with_context(|| {
            format!(
                "could not spawn peripheral proxy service {}",
                component_ref.id()
            )
        })?;
    }

    Ok(())
}
