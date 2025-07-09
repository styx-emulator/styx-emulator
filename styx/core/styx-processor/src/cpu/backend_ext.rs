// SPDX-License-Identifier: BSD-2-Clause
use styx_cpu_type::arch::{backends::ArchRegister, CpuRegister, RegisterValueCompatible};
use styx_errors::anyhow::anyhow;

use super::{
    backend::{ReadRegisterError, WriteRegisterError},
    CpuBackend,
};

impl<T: ?Sized + CpuBackend> CpuBackendExt for T {
    fn read_register<V: RegisterValueCompatible>(
        &mut self,
        reg: impl Into<ArchRegister>,
    ) -> Result<V::ReturnValue, ReadRegisterError> {
        let reg = reg.into();
        let val = self.read_register_raw(reg)?;
        let res = V::as_inner_value(val);
        match res {
            Ok(val) => Ok(val),
            Err(_) => Err(anyhow!("register value not compatible with {val:?}").into()),
        }
    }

    fn write_register(
        &mut self,
        reg: impl Into<ArchRegister>,
        value: impl RegisterValueCompatible,
    ) -> Result<(), WriteRegisterError> {
        let reg = reg.into();
        self.write_register_raw(reg, value.into())
    }

    // TODO: use the top level arch enum thing
    fn register_values(&mut self) -> Vec<(CpuRegister, u32)> {
        let registers = self.architecture().registers();
        registers
            .registers()
            .iter()
            .filter_map(|regdef| {
                let value = self
                    .read_register::<u32>(regdef.variant())
                    .map(Some)
                    .unwrap_or_else(|err| {
                        // this is needed to handle registers that are not u32
                        log::warn!(
                            "Could not get the register value for {:?}: {err:#}",
                            regdef.variant()
                        );
                        None
                    });
                value.map(|v| (regdef.clone(), v))
            })
            .collect()
    }
}

pub trait CpuBackendExt {
    /// Reads the value of the desired register from the target cpu.
    ///
    /// This method should error if the register is not available on the target,
    /// and if the value provided is not the correct size for the register.
    fn read_register<V: RegisterValueCompatible>(
        &mut self,
        reg: impl Into<ArchRegister>,
    ) -> Result<V::ReturnValue, ReadRegisterError>;

    /// Write a value to a register on the target cpu.
    ///
    /// This method should error if the register is not available on the target,
    /// and if the value provided is not the correct size for the register.
    fn write_register(
        &mut self,
        reg: impl Into<ArchRegister>,
        value: impl RegisterValueCompatible,
    ) -> Result<(), WriteRegisterError>;

    /// Get current register values for the [`crate::processor::Processor`] being emulated.
    ///
    /// The returned vec is in the same order as the [`styx_cpu_type::arch::ArchitectureDef`]
    /// registers.
    // TODO: use the top level arch enum thing
    fn register_values(&mut self) -> Vec<(CpuRegister, u32)>;
}
