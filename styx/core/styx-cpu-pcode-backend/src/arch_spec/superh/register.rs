// SPDX-License-Identifier: BSD-2-Clause
use styx_cpu_type::arch::backends::ArchRegister;
use styx_processor::cpu::CpuBackend;

use crate::memory::sized_value::SizedValue;
use crate::register_manager::{RegisterCallback, RegisterCallbackCpu, RegisterHandleError};

#[derive(Debug, Default)]
pub struct FloatingPointExtensionHandler {
    value: u64,
}

impl<T: CpuBackend> RegisterCallback<T> for FloatingPointExtensionHandler {
    fn read(
        &mut self,
        _register: ArchRegister,
        _cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<SizedValue, RegisterHandleError> {
        Ok(SizedValue::from_u64(self.value, 4))
    }

    fn write(
        &mut self,
        _register: ArchRegister,
        value: SizedValue,
        _cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<(), RegisterHandleError> {
        self.value = value.to_u64().unwrap();

        Ok(())
    }
}
