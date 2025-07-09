// SPDX-License-Identifier: BSD-2-Clause
//! Async runtime for the processor.
//!
//! [Peripheral](super::event_controller::Peripheral)s and [Plugin](super::plugins::Plugin)s can use
//! the async runtime to run code, well, asynchronously!
//!
use tokio::runtime::{Builder, Handle, Runtime};

/// Async runtime for a processor.
///
/// Access and spawn tasks using [ProcessorRuntime::handle()].
pub struct ProcessorRuntime {
    runtime: Runtime,
}

impl Default for ProcessorRuntime {
    fn default() -> Self {
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build processor tokio runtime");

        Self { runtime }
    }
}

impl ProcessorRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn handle(&self) -> Handle {
        self.runtime.handle().clone()
    }
}
