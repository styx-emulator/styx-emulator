// SPDX-License-Identifier: BSD-2-Clause
use styx_emulator::core::executor::DefaultExecutor;
use styx_emulator::cpu::arch::superh::SuperHVariants;
use styx_emulator::plugins::{debug_tools::*, tracing_plugins::ProcessorTracingPlugin};
use styx_emulator::prelude::*;
use styx_emulator::processors::RawProcessor;
use tracing::info;

/// path to yaml description, see [`ParameterizedLoader`] for more
const LOAD_YAML: &str = "load.yaml";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut proc = ProcessorBuilder::default()
        .with_builder(RawProcessor::new(
            Arch::SuperH,
            SuperHVariants::SH2A,
            ArchEndian::BigEndian,
        ))
        .with_loader(ParameterizedLoader)
        .with_executor(DefaultExecutor)
        .add_plugin(ProcessorTracingPlugin)
        .add_plugin(UnmappedMemoryFaultPlugin::new(true))
        .add_plugin(ProtectedMemoryFaultPlugin::new(true))
        .with_target_program(LOAD_YAML)
        .build()?;

    info!("Starting emulator");

    proc.run(Forever)?;

    Ok(())
}
