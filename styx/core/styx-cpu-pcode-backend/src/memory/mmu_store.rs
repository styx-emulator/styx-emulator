// SPDX-License-Identifier: BSD-2-Clause
use styx_cpu_type::ArchEndian;
use styx_pcode::pcode::SpaceInfo;
use styx_processor::{
    cpu::CpuBackend,
    memory::{
        helpers::{ReadExt, WriteExt},
        Mmu, MmuOpError,
    },
};

use crate::memory::sized_value::SizedValue;

use super::space::SpaceError;

/// Single address space with backing data store.
#[derive(Debug)]
pub(crate) struct MmuSpace {
    /// Metadata about space.
    pub(crate) info: SpaceInfo,
}

impl MmuSpace {
    pub(crate) fn new(info: SpaceInfo) -> Self {
        Self { info }
    }

    /// Get <=16 bytes from any offset, corrected for endianess.
    pub(crate) fn get_value(
        &self,
        mmu: &mut Mmu,
        cpu: &mut dyn CpuBackend,
        offset: u64,
        size: u8,
    ) -> Result<SizedValue, SpaceError> {
        let mut buf = [0u8; SizedValue::SIZE_BYTES];
        let buf_ref = &mut buf[0..size as usize];
        self.get_chunk(mmu, cpu, offset, buf_ref)?;

        let value = match self.info.endian {
            ArchEndian::LittleEndian => SizedValue::from_le_bytes(buf_ref),
            ArchEndian::BigEndian => SizedValue::from_be_bytes(buf_ref),
        };
        Ok(value)
    }
    /// Set <=16 bytes to any offset, corrected for endianess.
    pub(crate) fn set_value(
        &self,
        mmu: &mut Mmu,
        cpu: &mut dyn CpuBackend,
        offset: u64,
        value: SizedValue,
    ) -> Result<(), SpaceError> {
        let mut bytes_buf = [0u8; SizedValue::SIZE_BYTES];
        let bytes = match self.info.endian {
            ArchEndian::LittleEndian => value.to_le_bytes(&mut bytes_buf),
            ArchEndian::BigEndian => value.to_be_bytes(&mut bytes_buf),
        };

        self.set_chunk(mmu, cpu, offset, bytes).map_err(Into::into)
    }

    /// Get bytes from any offset.
    pub(crate) fn get_chunk(
        &self,
        mmu: &mut Mmu,
        cpu: &mut dyn CpuBackend,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<(), MmuOpError> {
        // todo code vs data here?
        mmu.virt_data(cpu).read(offset).bytes(buf)?;
        Ok(())
    }
    /// Set bytes to any offset.
    pub(crate) fn set_chunk(
        &self,
        mmu: &mut Mmu,
        cpu: &mut dyn CpuBackend,
        offset: u64,
        buf: &[u8],
    ) -> Result<(), MmuOpError> {
        mmu.virt_data(cpu).write(offset).bytes(buf)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use styx_pcode::pcode::SpaceId;
    use styx_processor::cpu::DummyBackend;

    use super::*;

    fn get_info(endian: ArchEndian) -> SpaceInfo {
        SpaceInfo {
            word_size: 4,
            address_size: 4,
            endian,
            id: SpaceId::Integer(1),
        }
    }

    /// simple read from mmuspace
    #[test]
    fn test_simple() {
        let mut mmu = Mmu::default();
        let mut cpu = DummyBackend;

        let mmu_store = MmuSpace::new(get_info(ArchEndian::LittleEndian));

        mmu.data().write(0x100).le().u32(0xdeadbeef).unwrap();

        let read = mmu_store.get_value(&mut mmu, &mut cpu, 0x100, 4).unwrap();
        assert_eq!(read.to_u128().unwrap(), 0xdeadbeef)
    }

    /// simple read from mmuspace but big endian
    #[test]
    fn test_big_endian() {
        let mut mmu = Mmu::default();
        let mut cpu = DummyBackend;

        let mmu_store = MmuSpace::new(get_info(ArchEndian::BigEndian));

        mmu.data().write(0x100).be().u32(0xdeadbeef).unwrap();

        let read = mmu_store.get_value(&mut mmu, &mut cpu, 0x100, 4).unwrap();
        assert_eq!(read.to_u128().unwrap(), 0xdeadbeef)
    }
}
