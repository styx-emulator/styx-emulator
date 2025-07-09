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
