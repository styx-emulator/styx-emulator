// SPDX-License-Identifier: BSD-2-Clause

use derive_more::Debug;
use log::info;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
};

use styx_cpu_type::{
    arch::{backends::GlobalArchRegister, RegisterValue, RegisterValueCompatible},
    ArchEndian,
};
use styx_errors::{
    anyhow::{anyhow, Context},
    UnknownError,
};

use super::{CpuBackend, ReadRegisterError, WriteRegisterError};

/// This trait is used in the `VcpuBuilder`
/// to provide shared state among each Vcpu,
/// when the `VcpuBuilder` is building all cpus.
pub trait CpuBuilding {
    /// For building a VcpuBundle, this will provide
    /// the shared register store. It's up to the backend
    /// to take the registers and add it to its handler.
    fn add_global_registers(
        &mut self,
        _register_store: Arc<Box<dyn GlobalRegisterStore>>,
    ) -> Result<(), UnknownError> {
        Ok(())
    }
}

/// Blanket default implementation
impl CpuBuilding for dyn CpuBackend {}
impl CpuBuilding for Box<dyn CpuBackend> {}

pub trait GlobalRegisterStore: Send + Sync + Debug {
    fn initialize(&mut self, regs_size: usize) -> Result<(), UnknownError>;
    fn write_register_raw(
        &self,
        reg_offset: usize,
        value: RegisterValue,
        endian: ArchEndian,
    ) -> Result<(), WriteRegisterError>;
    fn read_register_raw(
        &self,
        reg: usize,
        size: usize,
        endian: ArchEndian,
    ) -> Result<RegisterValue, ReadRegisterError>;
}

impl GlobalRegisterStore for RwLock<Vec<u8>> {
    fn write_register_raw(
        &self,
        reg_offset: usize,
        value: RegisterValue,
        endian: ArchEndian,
    ) -> Result<(), WriteRegisterError> {
        info!("global write {reg_offset:x?} val {value:x?}");
        let mut locked = self
            .write()
            .expect("Couldn't acquire lock for global register store");

        match value {
            RegisterValue::u8(v) => locked[reg_offset] = v,
            RegisterValue::u16(v) => {
                locked[reg_offset..(reg_offset + 2)].copy_from_slice(&match endian {
                    ArchEndian::LittleEndian => v.to_le_bytes(),
                    ArchEndian::BigEndian => v.to_be_bytes(),
                })
            }
            RegisterValue::u32(v) => {
                locked[reg_offset..(reg_offset + 4)].copy_from_slice(&match endian {
                    ArchEndian::LittleEndian => v.to_le_bytes(),
                    ArchEndian::BigEndian => v.to_be_bytes(),
                })
            }
            RegisterValue::u64(v) => {
                locked[reg_offset..(reg_offset + 8)].copy_from_slice(&match endian {
                    ArchEndian::LittleEndian => v.to_le_bytes(),
                    ArchEndian::BigEndian => v.to_be_bytes(),
                })
            }
            RegisterValue::u128(v) => {
                locked[reg_offset..(reg_offset + 16)].copy_from_slice(&match endian {
                    ArchEndian::LittleEndian => v.to_le_bytes(),
                    ArchEndian::BigEndian => v.to_be_bytes(),
                })
            }
            _ => unimplemented!(),
        }
        Ok(())
    }

    fn read_register_raw(
        &self,
        reg: usize,
        size: usize,
        endian: ArchEndian,
    ) -> Result<RegisterValue, ReadRegisterError> {
        let locked = self
            .read()
            .expect("Couldn't acquire lock for global register store");

        // We expect that the store is filled beforehand

        let value = &locked[reg..(reg + size)];

        info!("global read {reg:?} val {value:x?}");
        let val = match size {
            1 => RegisterValue::u8(value[0]),
            2 => RegisterValue::u16(match endian {
                ArchEndian::LittleEndian => u16::from_le_bytes(value.try_into().unwrap()),
                ArchEndian::BigEndian => u16::from_be_bytes(value.try_into().unwrap()),
            }),
            4 => RegisterValue::u32(match endian {
                ArchEndian::LittleEndian => u32::from_le_bytes(value.try_into().unwrap()),
                ArchEndian::BigEndian => u32::from_be_bytes(value.try_into().unwrap()),
            }),
            8 => RegisterValue::u64(match endian {
                ArchEndian::LittleEndian => u64::from_le_bytes(value.try_into().unwrap()),
                ArchEndian::BigEndian => u64::from_be_bytes(value.try_into().unwrap()),
            }),
            16 => RegisterValue::u128(match endian {
                ArchEndian::LittleEndian => u128::from_le_bytes(value.try_into().unwrap()),
                ArchEndian::BigEndian => u128::from_be_bytes(value.try_into().unwrap()),
            }),
            _ => unimplemented!(),
        };

        Ok(val)
    }

    fn initialize(&mut self, regs_size: usize) -> Result<(), UnknownError> {
        let mut locked = self
            .write()
            .expect("Couldn't acquire lock for global register store");

        // Allocate the registers
        locked.extend_from_slice(&vec![0; regs_size]);

        Ok(())
    }
}
