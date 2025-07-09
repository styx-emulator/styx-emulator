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
use crate::{memory::sized_value::SizedValue, PCodeStateChange, PcodeBackend};

use super::{CallOtherCallback, CallOtherHandleError};
use log::trace;
use std::fmt::Debug;
use styx_pcode::pcode::VarnodeData;
use styx_processor::{event_controller::EventController, memory::Mmu};

#[derive(Debug)]
pub struct TraceCallOther {
    debug_string: Box<str>,
}
impl TraceCallOther {
    pub fn new(debug_string: Box<str>) -> Self {
        Self { debug_string }
    }
}
impl CallOtherCallback for TraceCallOther {
    fn handle(
        &mut self,
        _cpu: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        trace!("{}", self.debug_string);
        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct CountLeadingZeros;
impl CallOtherCallback for CountLeadingZeros {
    fn handle(
        &mut self,
        cpu: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug_assert_eq!(inputs.len(), 1);
        debug_assert!(output.is_some());

        let value = cpu.read(&inputs[0]).unwrap().to_u128().unwrap();
        // extra_zeros = bits_in_u64 - bits in input value
        let extra_zeros = 64 - (inputs[0].size * 8);
        let leading_zeros = value.leading_zeros() - extra_zeros;

        cpu.write(
            output.unwrap(),
            SizedValue::from_u128(leading_zeros as u128, inputs[0].size as u8),
        )
        .unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

/// [CallOtherCallback] that does nothing.
///
/// Used for user ops that don't have an effect on emulation, like cache and
/// instruction synchronization.
#[derive(Debug)]
pub struct EmptyCallback;
impl CallOtherCallback for EmptyCallback {
    fn handle(
        &mut self,
        _cpu: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        // do nothing
        Ok(PCodeStateChange::Fallthrough)
    }
}
