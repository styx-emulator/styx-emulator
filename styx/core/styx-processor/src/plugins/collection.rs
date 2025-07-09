// SPDX-License-Identifier: BSD-2-Clause
//! Containers for holding and performing common operations on many [`Plugin`]s.
//!
use log::debug;
use styx_errors::UnknownError;

use crate::{core::ProcessorCore, processor::BuildingProcessor};

use super::{Plugin, UninitPlugin};

/// Collection of plugins in the processor.
pub struct PluginsContainer<T> {
    pub(crate) plugins: Vec<T>,
}

impl<T> Default for PluginsContainer<T> {
    fn default() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }
}

pub type Plugins = PluginsContainer<Box<dyn Plugin>>;

impl PluginsContainer<Box<dyn UninitPlugin>> {
    /// Initialize all plugins, returning a new collection of initialized plugins.
    pub(crate) fn init_all(
        self,
        proc: &mut BuildingProcessor,
    ) -> Result<PluginsContainer<Box<dyn Plugin>>, UnknownError> {
        debug!("initializing plugins");
        let plugins_result: Result<Vec<_>, _> =
            self.plugins.into_iter().map(|p| p.init(proc)).collect();

        plugins_result.map(|plugins| PluginsContainer { plugins })
    }
}

impl PluginsContainer<Box<dyn Plugin>> {
    /// Trigger the plugins_initialized_hook for all plugins.
    pub(crate) fn post_init_all(
        &mut self,
        proc: &mut BuildingProcessor,
    ) -> Result<(), UnknownError> {
        debug!("initializing plugins");
        for plugin in self.plugins.iter_mut() {
            plugin.plugins_initialized_hook(proc)?;
        }
        Ok(())
    }

    /// Called on processor start. Called each time the processor is started after pause.
    pub fn on_processor_start(&mut self, core: &mut ProcessorCore) -> Result<(), UnknownError> {
        for plugin in self.plugins.iter_mut() {
            plugin.on_processor_start(core)?;
        }
        Ok(())
    }

    /// Called on processor stop. Called each time the processor is pause.
    pub fn on_processor_stop(&mut self, core: &mut ProcessorCore) -> Result<(), UnknownError> {
        for plugin in self.plugins.iter_mut() {
            plugin.on_processor_stop(core)?;
        }
        Ok(())
    }

    /// Tick all plugins.
    pub fn tick(&mut self, core: &mut ProcessorCore) -> Result<(), UnknownError> {
        for plugin in self.plugins.iter_mut() {
            plugin.tick(core)?;
        }
        Ok(())
    }
}
