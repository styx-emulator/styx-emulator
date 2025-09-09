use styx_core::prelude::*;

#[derive(serde::Deserialize)]
pub struct PcsConfiguration {
    connection: String,
}

/// Put on processors in a PCS system to translate incoming peripheral traffic.
pub struct PcsClientPlugin {}

impl UninitPlugin for PcsClientPlugin {
    fn init(
        self: Box<Self>,
        proc: &mut BuildingProcessor,
    ) -> Result<Box<dyn Plugin>, UnknownError> {
        todo!()
    }
}

impl Plugin for PcsClientPlugin {
    fn on_processor_start(&mut self, _core: &mut ProcessorCore) -> Result<(), UnknownError> {
        Ok(())
    }

    fn on_processor_stop(&mut self, _core: &mut ProcessorCore) -> Result<(), UnknownError> {
        Ok(())
    }

    fn tick(&mut self, _core: &mut ProcessorCore) -> Result<(), UnknownError> {
        Ok(())
    }

    fn plugins_initialized_hook(
        &mut self,
        _proc: &mut BuildingProcessor,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    fn name(&self) -> &str {
        todo!()
    }
}
