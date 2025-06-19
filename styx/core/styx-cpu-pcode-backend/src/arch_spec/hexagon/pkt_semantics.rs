// SPDX-License-Identifier: BSD-2-Clause
use log::trace;
use styx_errors::anyhow::Context;
use styx_pcode::pcode::VarnodeData;
use styx_processor::{cpu::CpuBackend, event_controller::EventController, memory::Mmu};

use crate::{
    call_other::{CallOtherCallback, CallOtherCpu, CallOtherHandleError},
    PCodeStateChange,
};

// See the Hexagon slaspec for more details,
// this constant is also defined there.
pub const DEST_REG_OFFSET: u64 = 0x600;

// For dotnew
#[derive(Debug)]
pub struct NewReg {}

impl<T: CpuBackend> CallOtherCallback<T> for NewReg {
    fn handle(
        &mut self,
        backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug_assert_eq!(inputs.len(), 1);
        debug_assert!(output.is_some());

        let mut input = inputs[0].clone();
        input.offset += DEST_REG_OFFSET;
        let reg_val = backend
            .read(&input)
            .with_context(|| "couldn't read the register's new value")?;

        // For now, since there are no packet semantics, we should just
        // use the previously set value.
        trace!("newreg varnode input is {input}");

        backend
            .write(output.unwrap(), reg_val)
            .with_context(|| "couldn't write the dotnew value to the specified output varnode")?;

        Ok(PCodeStateChange::Fallthrough)
    }
}
