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
#![allow(dead_code, unused_variables)]
use super::super::communications_processor::CpmPeripheral;
use styx_core::{errors::UnknownError, prelude::*};

#[derive(Debug)]
pub struct SystemControlClock;

impl Peripheral for SystemControlClock {
    fn init(
        &mut self,
        proc: &mut styx_core::prelude::BuildingProcessor,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    fn name(&self) -> &str {
        "System Control Clock"
    }
}

impl CpmPeripheral for SystemControlClock {
    fn process_cpm_opcode(
        &self,
        opcode: crate::communications_processor::CpmOpcode,
    ) -> Result<(), crate::communications_processor::CpmError> {
        Ok(())
    }

    fn process_event(
        &self,
        evt: crate::communications_processor::CpmEventType,
    ) -> Result<(), crate::communications_processor::CpmError> {
        Ok(())
    }

    fn reset(&self) -> Result<(), crate::communications_processor::CpmError> {
        Ok(())
    }

    fn new_arc(
        variant: crate::Mpc8xxVariants,
        cpm: Weak<crate::communications_processor::CommunicationsProcessorModule>,
        idx: Option<usize>,
    ) -> Result<Arc<Self>, crate::communications_processor::CpmError>
    where
        Self: Sized,
    {
        Ok(Arc::new_cyclic(|me| Self {}))
    }
}

#[derive(Debug)]
pub struct PllClock;

impl Peripheral for PllClock {
    fn init(
        &mut self,
        proc: &mut styx_core::prelude::BuildingProcessor,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    fn name(&self) -> &str {
        "Pll Clock"
    }
}

impl CpmPeripheral for PllClock {
    fn process_cpm_opcode(
        &self,
        opcode: crate::communications_processor::CpmOpcode,
    ) -> Result<(), crate::communications_processor::CpmError> {
        Ok(())
    }

    fn process_event(
        &self,
        evt: crate::communications_processor::CpmEventType,
    ) -> Result<(), crate::communications_processor::CpmError> {
        Ok(())
    }

    fn reset(&self) -> Result<(), crate::communications_processor::CpmError> {
        Ok(())
    }

    fn new_arc(
        variant: crate::Mpc8xxVariants,
        cpm: Weak<crate::communications_processor::CommunicationsProcessorModule>,
        idx: Option<usize>,
    ) -> Result<Arc<Self>, crate::communications_processor::CpmError>
    where
        Self: Sized,
    {
        Ok(Arc::new_cyclic(|me| Self {}))
    }
}
