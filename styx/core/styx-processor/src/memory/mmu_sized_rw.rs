// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
use paste;
use styx_errors::UnknownError;

use super::Mmu;
use crate::memory::physical::address_space::MemoryImpl;
use crate::memory::MemoryOperation;

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
            pub fn [<read_ $type _le_virt_data>](&mut self, addr: u64) -> Result<$type, UnknownError> {
                let mut data = [0_u8;std::mem::size_of::<$type>()];
                let phys_addr = self.tlb.translate_va_data(addr, MemoryOperation::Read)?;
                self.memory.read_data(phys_addr, data.as_mut_slice())?;
                Ok($type::from_le_bytes(data))
            }

            #[doc = "Read from data as big endian bytes using a virtual address"]
            pub fn [<read_ $type _be_virt_data>](&mut self, addr: u64) -> Result<$type, UnknownError> {
                let mut data = [0_u8;std::mem::size_of::<$type>()];
                let phys_addr = self.tlb.translate_va_data(addr, MemoryOperation::Read)?;
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
            pub fn [<read_ $type _le_virt_code>](&mut self, addr: u64) -> Result<$type, UnknownError> {
                let mut data = [0_u8;std::mem::size_of::<$type>()];
                let phys_addr = self.tlb.translate_va_code(addr)?;
                self.memory.read_code(phys_addr, data.as_mut_slice())?;
                Ok($type::from_le_bytes(data))
            }

            #[doc = "Read from code as big endian bytes using a virtual address"]
            pub fn [<read_ $type _be_virt_code>](&mut self, addr: u64) -> Result<$type, UnknownError> {
                let mut data = [0_u8;std::mem::size_of::<$type>()];
                let phys_addr = self.tlb.translate_va_code(addr)?;
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

            pub fn [<write_ $type _le_virt_data>](&mut self, addr: u64, val: $type) -> Result<(), UnknownError> {
                let data = $type::to_le_bytes(val);
                let phys_addr = self.tlb.translate_va_data(addr, MemoryOperation::Write)?;
                self.memory.write_data(phys_addr, &data)?;
                Ok(())
            }

            pub fn [<write_ $type _be_virt_data>](&mut self, addr: u64, val: $type) -> Result<(), UnknownError> {
                let data = $type::to_be_bytes(val);
                let phys_addr = self.tlb.translate_va_data(addr, MemoryOperation::Write)?;
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

            pub fn [<write_ $type _le_virt_code>](&mut self, addr: u64, val: $type) -> Result<(), UnknownError> {
                let data = $type::to_le_bytes(val);
                let phys_addr = self.tlb.translate_va_code(addr)?;
                self.memory.write_code(phys_addr, &data)?;
                Ok(())
            }

            pub fn [<write_ $type _be_virt_code>](&mut self, addr: u64, val: $type) -> Result<(), UnknownError> {
                let data = $type::to_be_bytes(val);
                let phys_addr = self.tlb.translate_va_code(addr)?;
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
