// SPDX-License-Identifier: BSD-2-Clause
use log::trace;
use styx_cpu_type::arch::{
    backends::{ArchRegister, BasicArchRegister},
    hexagon::HexagonRegister,
    RegisterValue,
};
use styx_errors::UnknownError;
use styx_pcode::pcode::VarnodeData;
use styx_processor::{
    cpu::{CpuBackend, CpuBackendExt},
    event_controller::EventController,
    hooks::{CoreHandle, RegisterReadHook, RegisterWriteHook},
    memory::Mmu,
};

use crate::{
    call_other::{CallOtherCallback, CallOtherHandleError},
    memory::sized_value::SizedValue,
    register_manager::{RegisterCallback, RegisterHandleError},
    PCodeStateChange, PcodeBackend,
};

pub const DEST_REG_OFFSET: u64 = 0x600;

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
        // Not happy about clones
        let mut input = inputs[0].clone();
        input.offset = input.offset + DEST_REG_OFFSET;
        let reg_val = backend.read(&input).unwrap();

        // For now, since there are no packet semantics, we should just
        // use the previously set value.
        //
        // TODO: update when packet semantics come into play
        trace!("newreg varnode input is {}", input);

        backend.write(output.unwrap(), reg_val).unwrap();

        Ok(PCodeStateChange::Fallthrough)
    }
}

// For now the backing storage will be here
#[derive(Debug, Default)]
pub struct PredicateAnd {
    // Number of times the predicate register was set in the packet
    no_sets_in_pkt: usize,
}

impl PredicateAnd {
    pub fn new() -> Self {
        Self { no_sets_in_pkt: 0 }
    }
}

impl RegisterReadHook for PredicateAnd {
    // We should only ever trap this for destination predicate regs
    // meaning that this *should* only be called at the end of a packet
    // when flushing registers.
    fn call(
        &mut self,
        proc: CoreHandle,
        register: ArchRegister,
        data: &mut RegisterValue,
    ) -> Result<(), UnknownError> {
        Ok(())
    }
    /*fn call(
        &mut self,
        register: ArchRegister,
        cpu: &mut PcodeBackend,
    ) -> Result<SizedValue, RegisterHandleError> {
        // Now that we are at the end of a packet, we should clear out the packet sets
        self.no_sets_in_pkt = 0;

        Ok(SizedValue::from(
            cpu.read_register::<u8>(register)
                .map_err(|e| RegisterHandleError::Other(e.into()))?,
        ))
    }*/
}

impl RegisterWriteHook for PredicateAnd {
    fn call(
        &mut self,
        proc: CoreHandle,
        register: ArchRegister,
        data: &RegisterValue,
    ) -> Result<(), UnknownError> {
        Ok(())
    }
    /*fn write(
        &mut self,
        register: ArchRegister,
        value: SizedValue,
        cpu: &mut PcodeBackend,
    ) -> Result<(), RegisterHandleError> {
        trace!("writing a predicate destination register...");

        let value_unwrap = value.to_u64().unwrap() as u8;

        let write_value = if self.no_sets_in_pkt > 0 {
            trace!("Predicate was written more than once in a packet, ANDing");

            let p_n = cpu
                .read_register::<u8>(register)
                .map_err(|e| RegisterHandleError::Other(e.into()))?;

            // AND logically, but true is 0xff
            if p_n & value_unwrap == 0xff {
                0xff
            } else {
                0x0
            }
        } else {
            value_unwrap
        };

        cpu.write_register(register, write_value).unwrap();
        self.no_sets_in_pkt += 1;

        Ok(())
    }*/
}
