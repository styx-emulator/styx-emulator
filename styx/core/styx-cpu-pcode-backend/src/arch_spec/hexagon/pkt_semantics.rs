use log::trace;
use styx_pcode::pcode::VarnodeData;
use styx_processor::{event_controller::EventController, memory::Mmu};

use crate::{
    call_other::{CallOtherCallback, CallOtherHandleError},
    memory::sized_value::SizedValue,
    PCodeStateChange, PcodeBackend,
};

// For dotnew
#[derive(Debug)]
pub struct NewReg {}

impl CallOtherCallback for NewReg {
    fn handle(
        &mut self,
        backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug_assert_eq!(inputs.len(), 1);
        debug_assert!(output.is_some());

        // Should I be unwrapping?
        let input = &inputs[0];
        let reg_val = backend.read(input).unwrap();

        // For now, since there are no packet semantics, we should just
        // use the previously set value.
        //
        // TODO: update when packet semantics come into play
        trace!("newreg varnode input is {}", input);

        backend.write(output.unwrap(), reg_val).unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}
