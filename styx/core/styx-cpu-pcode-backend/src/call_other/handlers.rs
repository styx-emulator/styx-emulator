// SPDX-License-Identifier: BSD-2-Clause
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
