// SPDX-License-Identifier: BSD-2-Clause

use clap::ValueEnum;
use styx_emulator::{
    errors::UnknownError, hooks::StyxHook, prelude::Processor,
    processors::hexagon::hexagon::HexagonProcessorConfig,
};

pub(crate) mod pixel5;
pub(crate) mod s22;
pub(crate) mod tester;

#[derive(Clone, ValueEnum, Debug)]
pub enum HexagonTarget {
    S22,
    Pixel5,
    Tester,
}

pub trait HexagonDevice {
    // Returns a list of `StyxHook`s, which are added. Runs after the `ProcessorBuilder`
    // finishes but before `Self::post_init`.
    fn hooks(&self) -> Result<Vec<StyxHook>, UnknownError>;
    // Returns the processor config, which is passed to the builder and used to
    // set up both the processor and various Hexagon peripherals.
    fn proc_config(&self) -> Result<HexagonProcessorConfig, UnknownError>;
    // To do fixups. Is sort of unsafe, since it could overwrite anything of the above,
    // Runs after the previous two functions. Use at your own risk for fixups that aren't
    // covered by the other two.
    fn post_init(&self, proc: &mut Processor) -> Result<(), UnknownError>;
}
