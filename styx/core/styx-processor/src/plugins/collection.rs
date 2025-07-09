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
