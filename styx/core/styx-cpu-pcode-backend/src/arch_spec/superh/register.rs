// SPDX-License-Identifier: BSD-2-Clause
use crate::{
    memory::sized_value::SizedValue,
    register_manager::{RegisterCallback, RegisterHandleError},
    PcodeBackend,
};
use styx_cpu_type::arch::backends::ArchRegister;

#[derive(Debug, Default)]
pub struct FloatingPointExtensionHandler {
    value: u64,
}

impl RegisterCallback for FloatingPointExtensionHandler {
    fn read(
        &mut self,
        _register: ArchRegister,
        _backend: &mut PcodeBackend,
    ) -> Result<SizedValue, RegisterHandleError> {
        Ok(SizedValue::from_u64(self.value, 4))
    }

    fn write(
        &mut self,
        _register: ArchRegister,
        value: SizedValue,
        _backend: &mut PcodeBackend,
    ) -> Result<(), RegisterHandleError> {
        self.value = value.to_u64().unwrap();

        Ok(())
    }
}
