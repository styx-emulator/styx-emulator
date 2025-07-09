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
//! SuperH2a Processor
use styx_core::core::builder::{BuildProcessorImplArgs, ProcessorImpl};
use styx_core::cpu::arch::superh::SuperHVariants;
use styx_core::cpu::arch::ArchEndian;
use styx_core::cpu::PcodeBackend;
use styx_core::event_controller::DummyEventController;
use styx_core::memory::MemoryPermissions;
use styx_core::prelude::*;

/// Partial Implementation of a SuperH2a processor
///
/// Not implemented:
/// - no event controller
/// - no peripherals get attached
/// - no default memory maps setup besides [`0x0` -> `0xffffffff`]
#[derive(Default)]
pub struct SuperH2aBuilder;
impl SuperH2aBuilder {
    /// Note: This is the bare minimum and needs to be revisited
    fn setup_address_space(&self, mmu: &mut Mmu) -> Result<(), UnknownError> {
        mmu.memory_map(0, u32::MAX as u64, MemoryPermissions::all())?;
        Ok(())
    }
}

impl ProcessorImpl for SuperH2aBuilder {
    fn build(&self, args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError> {
        let cpu = if let Backend::Pcode = args.backend {
            Box::new(PcodeBackend::new_engine_config(
                SuperHVariants::SH2A,
                ArchEndian::BigEndian,
                &args.into(),
            ))
        } else {
            return Err(anyhow!("sh2 processor only supports pcode backend"));
        };

        let mut mmu = Mmu::default_region_store();

        self.setup_address_space(&mut mmu)?;

        let mut hints = LoaderHints::new();
        hints.insert("arch".to_owned().into_boxed_str(), Box::new(Arch::SuperH));

        Ok(ProcessorBundle {
            cpu,
            mmu,
            event_controller: Box::new(DummyEventController::default()),
            peripherals: Vec::new(),
            loader_hints: hints,
        })
    }
}
