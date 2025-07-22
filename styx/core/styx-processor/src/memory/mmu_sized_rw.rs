// SPDX-License-Identifier: BSD-2-Clause
use paste;
use styx_errors::UnknownError;

use super::{MemoryOperation, MemoryType, Mmu, TlbProcessor};
use crate::cpu::CpuBackend;
use crate::memory::physical::address_space::MemoryImpl;

/// For some input type `T`, this macro generates functions for reading and
/// writing memory as type `T`.
///
/// 16 functions are generated with each combination of {read, write},
/// {little endian, big endian}, {physical, virtual}, and {code, data}.
///
/// For example:
///
/// `mmu_sized_rw(u32)` will generate functions like `read_u32_le_phys_data(addr: u64)`,
/// which represents reading a u32 from data memory, treating `addr` as a physical
/// address, and reading bytes as little endian.
macro_rules! mmu_sized_rw {
    ($type:ty) => {
        paste::item! {
            #[doc = "Read from data as little endian bytes using a physical address"]
            pub fn [<read_ $type _le_phys_data>](&self, addr: u64) -> Result<$type, UnknownError> {
                let mut data = [0_u8;std::mem::size_of::<$type>()];
                self.memory.read_data(addr, data.as_mut_slice())?;
                Ok($type::from_le_bytes(data))
            }

            #[doc = "Read from data as big endian bytes using a physical address"]
            pub fn [<read_ $type _be_phys_data>](&self, addr: u64) -> Result<$type, UnknownError> {
                let mut data = [0_u8;std::mem::size_of::<$type>()];
                self.memory.read_data(addr, data.as_mut_slice())?;
                Ok($type::from_be_bytes(data))
            }

            #[doc = "Read from data as little endian bytes using a virtual address"]
            pub fn [<read_ $type _le_virt_data>](&mut self, addr: u64, cpu: &mut dyn CpuBackend) -> Result<$type, UnknownError> {
                let mut proc = TlbProcessor::new(&mut self.memory, cpu);
                let mut data = [0_u8;std::mem::size_of::<$type>()];
                let phys_addr = self.tlb.translate_va(addr, MemoryOperation::Read, MemoryType::Data, &mut proc)?;
                self.memory.read_data(phys_addr, data.as_mut_slice())?;
                Ok($type::from_le_bytes(data))
            }

            #[doc = "Read from data as big endian bytes using a virtual address"]
            pub fn [<read_ $type _be_virt_data>](&mut self, addr: u64, cpu: &mut dyn CpuBackend) -> Result<$type, UnknownError> {
                let mut proc = TlbProcessor::new(&mut self.memory, cpu);
                let mut data = [0_u8;std::mem::size_of::<$type>()];
                let phys_addr = self.tlb.translate_va(addr, MemoryOperation::Read, MemoryType::Data, &mut proc)?;
                self.memory.read_data(phys_addr, data.as_mut_slice())?;
                Ok($type::from_be_bytes(data))
            }

            #[doc = "Read from code as little endian bytes using a physical address"]
            pub fn [<read_ $type _le_phys_code>](&self, addr: u64) -> Result<$type, UnknownError> {
                let mut data = [0_u8;std::mem::size_of::<$type>()];
                self.memory.read_code(addr, data.as_mut_slice())?;
                Ok($type::from_le_bytes(data))
            }

            #[doc = "Read from code as big endian bytes using a physical address"]
            pub fn [<read_ $type _be_phys_code>](&self, addr: u64) -> Result<$type, UnknownError> {
                let mut data = [0_u8;std::mem::size_of::<$type>()];
                self.memory.read_code(addr, data.as_mut_slice())?;
                Ok($type::from_be_bytes(data))
            }

            #[doc = "Read from code as little endian bytes using a virtual address"]
            pub fn [<read_ $type _le_virt_code>](&mut self, addr: u64, cpu: &mut dyn CpuBackend) -> Result<$type, UnknownError> {
                let mut proc = TlbProcessor::new(&mut self.memory, cpu);
                let mut data = [0_u8;std::mem::size_of::<$type>()];
                let phys_addr = self.tlb.translate_va(addr, MemoryOperation::Read, MemoryType::Code, &mut proc)?;
                self.memory.read_code(phys_addr, data.as_mut_slice())?;
                Ok($type::from_le_bytes(data))
            }

            #[doc = "Read from code as big endian bytes using a virtual address"]
            pub fn [<read_ $type _be_virt_code>](&mut self, addr: u64, cpu: &mut dyn CpuBackend) -> Result<$type, UnknownError> {
                let mut proc = TlbProcessor::new(&mut self.memory, cpu);
                let mut data = [0_u8;std::mem::size_of::<$type>()];
                let phys_addr = self.tlb.translate_va(addr, MemoryOperation::Read, MemoryType::Code, &mut proc)?;
                self.memory.read_code(phys_addr, data.as_mut_slice())?;
                Ok($type::from_be_bytes(data))
            }

            pub fn [<write_ $type _le_phys_data>](&mut self, addr: u64, val: $type) -> Result<(), UnknownError> {
                let data = $type::to_le_bytes(val);
                self.memory.write_data(addr, &data)?;
                Ok(())
            }

            pub fn [<write_ $type _be_phys_data>](&mut self, addr: u64, val: $type) -> Result<(), UnknownError> {
                let data = $type::to_be_bytes(val);
                self.memory.write_data(addr, &data)?;
                Ok(())
            }

            pub fn [<write_ $type _le_virt_data>](&mut self, addr: u64, val: $type, cpu: &mut dyn CpuBackend) -> Result<(), UnknownError> {
                let mut proc = TlbProcessor::new(&mut self.memory, cpu);
                let data = $type::to_le_bytes(val);
                let phys_addr = self.tlb.translate_va(addr, MemoryOperation::Write, MemoryType::Data, &mut proc)?;
                self.memory.write_data(phys_addr, &data)?;
                Ok(())
            }

            pub fn [<write_ $type _be_virt_data>](&mut self, addr: u64, val: $type, cpu: &mut dyn CpuBackend) -> Result<(), UnknownError> {
                let mut proc = TlbProcessor::new(&mut self.memory, cpu);
                let data = $type::to_be_bytes(val);
                let phys_addr = self.tlb.translate_va(addr, MemoryOperation::Write, MemoryType::Data, &mut proc)?;
                self.memory.write_data(phys_addr, &data)?;
                Ok(())
            }

            pub fn [<write_ $type _le_phys_code>](&mut self, addr: u64, val: $type) -> Result<(), UnknownError> {
                let data = $type::to_le_bytes(val);
                self.memory.write_code(addr, &data)?;
                Ok(())
            }

            pub fn [<write_ $type _be_phys_code>](&mut self, addr: u64, val: $type) -> Result<(), UnknownError> {
                let data = $type::to_be_bytes(val);
                self.memory.write_code(addr, &data)?;
                Ok(())
            }

            pub fn [<write_ $type _le_virt_code>](&mut self, addr: u64, val: $type, cpu: &mut dyn CpuBackend) -> Result<(), UnknownError> {
                let mut proc = TlbProcessor::new(&mut self.memory, cpu);
                let data = $type::to_le_bytes(val);
                let phys_addr = self.tlb.translate_va(addr, MemoryOperation::Write, MemoryType::Code, &mut proc)?;
                self.memory.write_code(phys_addr, &data)?;
                Ok(())
            }

            pub fn [<write_ $type _be_virt_code>](&mut self, addr: u64, val: $type, cpu: &mut dyn CpuBackend) -> Result<(), UnknownError> {
                let mut proc = TlbProcessor::new(&mut self.memory, cpu);
                let data = $type::to_be_bytes(val);
                let phys_addr = self.tlb.translate_va(addr, MemoryOperation::Write, MemoryType::Code, &mut proc)?;
                self.memory.write_code(phys_addr, &data)?;
                Ok(())
            }
        }
    };
}

impl Mmu {
    mmu_sized_rw!(u8);
    mmu_sized_rw!(u16);
    mmu_sized_rw!(u32);
    mmu_sized_rw!(u64);
    mmu_sized_rw!(u128);
    mmu_sized_rw!(i8);
    mmu_sized_rw!(i16);
    mmu_sized_rw!(i32);
    mmu_sized_rw!(i64);
    mmu_sized_rw!(i128);
    mmu_sized_rw!(f32);
    mmu_sized_rw!(f64);
}
