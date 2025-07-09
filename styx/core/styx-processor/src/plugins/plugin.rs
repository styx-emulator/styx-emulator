// SPDX-License-Identifier: BSD-2-Clause
use static_assertions::assert_obj_safe;
use styx_errors::UnknownError;

use crate::{core::ProcessorCore, processor::BuildingProcessor};

assert_obj_safe!(UninitPlugin);

/// Represents a plugin in an uninitialized state.
///
/// The init method converts the uninitialized plugin into an initialized [`Plugin`]
pub trait UninitPlugin: Send {
    fn init(self: Box<Self>, proc: &mut BuildingProcessor)
        -> Result<Box<dyn Plugin>, UnknownError>;
}

assert_obj_safe!(Plugin);

/// The common interface for all Styx plugins.
///
/// Represents an initialized plugin.
pub trait Plugin: Send {
    /// The name of the plugin.
    fn name(&self) -> &str;

    /// Called on processor start. Called each time the processor is started after pause.
    fn on_processor_start(&mut self, _core: &mut ProcessorCore) -> Result<(), UnknownError> {
        Ok(())
    }

    /// Called on processor stop. Called each time the processor is pause.
    fn on_processor_stop(&mut self, _core: &mut ProcessorCore) -> Result<(), UnknownError> {
        Ok(())
    }

    /// Called every so often to advance the plugin's state.
    fn tick(&mut self, _core: &mut ProcessorCore) -> Result<(), UnknownError> {
        Ok(())
    }

    /// Called after [`UninitPlugin::init()`] are called.
    ///
    /// Allows for code to run that requires initialized plugins.
    fn plugins_initialized_hook(
        &mut self,
        _proc: &mut BuildingProcessor,
    ) -> Result<(), UnknownError> {
        Ok(())
    }
}
