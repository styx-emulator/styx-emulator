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
