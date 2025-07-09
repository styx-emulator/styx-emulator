// SPDX-License-Identifier: BSD-2-Clause
use styx_cpu_type::arch::backends::ArchRegister;
use styx_errors::anyhow::Context;

use crate::{
    memory::sized_value::SizedValue,
    pcode_gen::RegisterTranslator,
    register_manager::{RegisterCallback, RegisterHandleError},
    PcodeBackend,
};

/// Handler for A0 and A1 to explicitly convert size from sla specs 8 bytes to styx's expected 5
/// bytes.
#[derive(Debug)]
pub(super) struct AnalogRegister;
impl RegisterCallback for AnalogRegister {
    fn read(
        &mut self,
        register: ArchRegister,
        cpu: &mut PcodeBackend,
    ) -> Result<SizedValue, RegisterHandleError> {
        let varnode = cpu.pcode_generator.get_register_expect(&register)?;

        let read_value = cpu
            .space_manager
            .read(varnode)
            .with_context(|| format!("failed to read {register:?} from {varnode:?}"))?;

        // analog registers are actually 40 bytes
        let read_value = read_value.resize(5);

        Ok(read_value)
    }

    fn write(
        &mut self,
        register: ArchRegister,
        value: SizedValue,
        cpu: &mut PcodeBackend,
    ) -> Result<(), RegisterHandleError> {
        let varnode = cpu.pcode_generator.get_register_expect(&register)?.clone();

        // sla spec size is 8 bytes
        // size 5 -> 8 loses no data
        let value = value.resize(8);

        cpu.space_manager
            .write(&varnode, value)
            .with_context(|| format!("failed to write {register:?} at {varnode:?}"))?;
        Ok(())
    }
}
