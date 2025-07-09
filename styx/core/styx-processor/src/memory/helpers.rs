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
//! Ergonomic APIs for reading from byte-addressable memory.
//!
//! The crux of the helpers is represented by two traits [`Readable`] and [`Writable`]. Combined,
//! these traits model memory operations by their single functions [`Readable::read_raw()`] and
//! [`Writable::write_raw()`]. A memory operation is an arbitrary length read or write starting at
//! an address which can error. The raw functions use slices to convey length and provide a mutable
//! buffer for reads and a readable buffer for writes. The error type is determined by the trait
//! implementor.
//!
//! # Usage
//!
//! Usage assumes you have found something that already implements the [`Readable`] and [`Writable`]
//! traits (e.g. [`Mmu::code()`](crate::memory::Mmu::code()) and
//! [`Mmu::data()`](crate::memory::Mmu::data())).
//!
//! ```
//! use styx_processor::memory::helpers::*;
//! use styx_processor::memory::*;
//!
//! let mut memory = Mmu::default();
//!
//! // write 0x1337 as 4-byte little-endian to address 0x1000
//! memory.data().write(0x1000).le().value(0x1337u32).unwrap();
//!
//! // read it back
//! let value = memory.data().read(0x1000).le().u32().unwrap();
//! assert_eq!(0x1337, value);
//! // verify byte representation
//! let byte_vec: Vec<u8> = memory.data().read(0x1000).vec(4).unwrap();
//! assert_eq!(&[0x37u8, 0x13u8, 0x00u8, 0x00u8], byte_vec.as_slice());
//! ```

use num::{
    cast::AsPrimitive,
    traits::{FromBytes, ToBytes},
};

use std::default::Default;

/// Read bytes starting from `addr` into a `bytes` slice.
///
/// Provides the [ReadExt] api.
///
/// Implementors provide a custom error type to express the correct error states.
///
/// # Example Implementation and Use
///
/// ```
/// # use styx_processor::memory::helpers::*;
/// struct CustomMemory {
///     memory: Vec<u8>,
/// }
/// #[derive(Debug)]
/// struct CustomMemoryError;
///
/// impl Readable for &CustomMemory {
///     type Error = CustomMemoryError;
///
///     fn read_raw(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
///         let size = bytes.len();
///         let max_idx = addr as usize + size;
///         if max_idx > self.memory.len() {
///             return Err(CustomMemoryError);
///         }
///
///         bytes.copy_from_slice(&self.memory[addr as usize..max_idx]);
///         Ok(())
///     }
/// }
///
/// let memory = CustomMemory {
///     memory: vec![0xca, 0xfe, 0xba, 0xbe],
/// };
///
/// assert_eq!(0xcafeu16, memory.read(0).be().u16().unwrap());
/// assert_eq!(0xcafebabeu32, memory.read(0).be().u32().unwrap());
/// let my_u16: u16 = memory.read(1).be().value().unwrap();
/// assert_eq!(0xfebau16, my_u16);
///
/// assert_eq!(0xfecau16, memory.read(0).le().u16().unwrap());
/// assert_eq!(0xbebafecau32, memory.read(0).le().u32().unwrap());
/// let my_u16: u16 = memory.read(1).le().value().unwrap();
/// assert_eq!(0xbafe, my_u16);
/// ```
///
pub trait Readable {
    type Error;

    fn read_raw(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), Self::Error>;
}

/// Read bytes starting from `addr` into a `bytes` slice.
///
/// Provides the [WriteExt] api.
///
/// Implementors provide a custom error type to express the correct error states.
pub trait Writable {
    type Error;

    fn write_raw(&mut self, addr: u64, bytes: &[u8]) -> Result<(), Self::Error>;
}

pub trait ReadExt: Sized {
    fn read(self, addr: impl AsPrimitive<u64>) -> MemoryRead<Self>;
}

impl<T: Readable> ReadExt for T {
    fn read(self, addr: impl AsPrimitive<u64>) -> MemoryRead<T> {
        MemoryRead {
            backing: self,
            addr: addr.as_(),
        }
    }
}

/// Memory read from an address.
pub struct MemoryRead<T> {
    backing: T,
    addr: u64,
}

impl<T: Readable> MemoryRead<T> {
    pub fn bytes(mut self, bytes: &mut [u8]) -> Result<(), T::Error> {
        Readable::read_raw(&mut self.backing, self.addr, bytes)
    }

    pub fn vec(mut self, size: usize) -> Result<Vec<u8>, T::Error> {
        let mut vec = vec![0; size];
        Readable::read_raw(&mut self.backing, self.addr, &mut vec)?;
        Ok(vec)
    }

    pub fn u8(self) -> Result<u8, T::Error> {
        let mut bytes = [0u8; 1];
        self.bytes(&mut bytes)?;
        Ok(bytes[0])
    }

    pub fn le(self) -> MemoryReadLe<T> {
        MemoryReadLe(self)
    }
    pub fn be(self) -> MemoryReadBe<T> {
        MemoryReadBe(self)
    }
}

pub struct MemoryReadLe<T>(MemoryRead<T>);

impl<T: Readable> MemoryReadLe<T> {
    pub fn unendian(self) -> MemoryRead<T> {
        self.0
    }

    pub fn value<V>(self) -> Result<V, T::Error>
    where
        V: FromBytes,
        V::Bytes: Default,
    {
        let mut bytes = V::Bytes::default();
        self.0.bytes(bytes.as_mut())?;
        let v = V::from_le_bytes(&bytes);
        Ok(v)
    }

    pub fn u16(self) -> Result<u16, T::Error> {
        self.value()
    }

    pub fn u32(self) -> Result<u32, T::Error> {
        self.value()
    }

    pub fn u64(self) -> Result<u64, T::Error> {
        self.value()
    }
}

pub struct MemoryReadBe<T>(MemoryRead<T>);
impl<T: Readable> MemoryReadBe<T> {
    pub fn unendian(self) -> MemoryRead<T> {
        self.0
    }

    pub fn value<V>(self) -> Result<V, T::Error>
    where
        V: FromBytes,
        V::Bytes: Default,
    {
        let mut bytes = V::Bytes::default();
        self.0.bytes(bytes.as_mut())?;
        let v = V::from_be_bytes(&bytes);
        Ok(v)
    }

    pub fn u16(self) -> Result<u16, T::Error> {
        self.value()
    }

    pub fn u32(self) -> Result<u32, T::Error> {
        self.value()
    }

    pub fn u64(self) -> Result<u64, T::Error> {
        self.value()
    }
}

pub trait WriteExt: Sized {
    fn write(self, addr: impl AsPrimitive<u64>) -> MemoryWrite<Self>;
}

impl<T: Writable> WriteExt for T {
    fn write(self, addr: impl AsPrimitive<u64>) -> MemoryWrite<T> {
        MemoryWrite {
            backing: self,
            addr: addr.as_(),
        }
    }
}

/// Memory write to an address.
pub struct MemoryWrite<T> {
    backing: T,
    addr: u64,
}

impl<T: Writable> MemoryWrite<T> {
    pub fn bytes(mut self, bytes: &[u8]) -> Result<(), T::Error> {
        Writable::write_raw(&mut self.backing, self.addr, bytes)
    }

    pub fn le(self) -> MemoryWriteLe<T> {
        MemoryWriteLe(self)
    }

    pub fn be(self) -> MemoryWriteBe<T> {
        MemoryWriteBe(self)
    }
}

pub struct MemoryWriteLe<T>(MemoryWrite<T>);
impl<T: Writable> MemoryWriteLe<T> {
    pub fn unendian(self) -> MemoryWrite<T> {
        self.0
    }

    /// Write any value that implements [ToBytes] in little endian order.
    pub fn value(self, value: impl ToBytes) -> Result<(), T::Error> {
        let bytes = value.to_le_bytes();
        self.0.bytes(bytes.as_ref())
    }

    pub fn u16(self, value: u16) -> Result<(), T::Error> {
        self.value(value)
    }

    pub fn u32(self, value: u32) -> Result<(), T::Error> {
        self.value(value)
    }

    pub fn u64(self, value: u64) -> Result<(), T::Error> {
        self.value(value)
    }
}

pub struct MemoryWriteBe<T>(MemoryWrite<T>);
impl<T: Writable> MemoryWriteBe<T> {
    pub fn unendian(self) -> MemoryWrite<T> {
        self.0
    }

    /// Write any value that implements [ToBytes] in little endian order.
    pub fn value(self, value: impl ToBytes) -> Result<(), T::Error> {
        let bytes = value.to_be_bytes();
        self.0.bytes(bytes.as_ref())
    }

    pub fn u16(self, value: u16) -> Result<(), T::Error> {
        self.value(value)
    }

    pub fn u32(self, value: u32) -> Result<(), T::Error> {
        self.value(value)
    }

    pub fn u64(self, value: u64) -> Result<(), T::Error> {
        self.value(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CustomMemory {
        memory: Vec<u8>,
    }
    #[derive(Debug)]
    struct CustomMemoryError;

    impl Readable for &CustomMemory {
        type Error = CustomMemoryError;

        fn read_raw(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
            let size = bytes.len();
            let max_idx = addr as usize + size;
            if max_idx > self.memory.len() {
                return Err(CustomMemoryError);
            }

            bytes.copy_from_slice(&self.memory[addr as usize..max_idx]);
            Ok(())
        }
    }

    #[test]
    fn test_various_reads() {
        let memory = CustomMemory {
            memory: vec![0xca, 0xfe, 0xba, 0xbe],
        };

        assert_eq!(0xcafeu16, memory.read(0).be().u16().unwrap());
        assert_eq!(0xcafebabeu32, memory.read(0).be().u32().unwrap());
        let my_u16: u16 = memory.read(1).be().value().unwrap();
        assert_eq!(0xfebau16, my_u16);

        assert_eq!(0xfecau16, memory.read(0).le().u16().unwrap());
        assert_eq!(0xbebafecau32, memory.read(0).le().u32().unwrap());
        let my_u16: u16 = memory.read(1).le().value().unwrap();
        assert_eq!(0xbafe, my_u16);
    }
}
