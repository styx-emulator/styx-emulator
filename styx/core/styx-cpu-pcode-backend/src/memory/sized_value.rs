// SPDX-License-Identifier: BSD-2-Clause
use std::fmt::{self, Debug, Display, UpperHex};

use arbitrary_int::Number;
use styx_cpu_type::{
    arch::{arm::SpecialArmRegisterValues, RegisterValue},
    ArchEndian,
};

use half::f16;
use thiserror::Error;

/// Arbitrary sized integer, optimized for u128 arithmetic.
///
/// Currently only supports <=16 bytes integers.
///
/// Consider using rug/GMP if larger ints are needed.
///
/// TODO: this is a prime candidate for kani/prusti verification tests
#[derive(Clone, Copy, PartialEq)]
pub struct SizedValue {
    value: u128,
    size: u8,
}

impl SizedValue {
    /// Number of bytes for the underlying storage of the [`SizedValue`].
    pub const SIZE_BYTES: usize = 16;
    /// Number of bits for the underlying storage of the [`SizedValue`].
    pub const SIZE_BITS: usize = Self::SIZE_BYTES * 8;
}

impl Debug for SizedValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let num_zeros = self.size as usize * 2;
        write!(f, "0x{:0num_zeros$X}", self.value, num_zeros = num_zeros)
    }
}

impl Display for SizedValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt::Display::fmt(&self.value, f)
    }
}

impl UpperHex for SizedValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt::UpperHex::fmt(&self.value, f)
    }
}

/// Create a mask of the bottom `alignment` bytes being 0xFF.
fn mask(bytes: u8) -> u128 {
    let mut start = 0xFF;
    for _ in 1..bytes {
        start <<= 8;
        start |= 0xFF;
    }
    start
}

impl From<u8> for SizedValue {
    fn from(value: u8) -> Self {
        SizedValue {
            value: value as u128,
            size: 1,
        }
    }
}

impl From<u16> for SizedValue {
    fn from(value: u16) -> Self {
        SizedValue {
            value: value as u128,
            size: 2,
        }
    }
}

impl From<u32> for SizedValue {
    fn from(value: u32) -> Self {
        SizedValue {
            value: value as u128,
            size: 4,
        }
    }
}

impl From<u64> for SizedValue {
    fn from(value: u64) -> Self {
        SizedValue {
            value: value as u128,
            size: 8,
        }
    }
}

impl From<u128> for SizedValue {
    fn from(value: u128) -> Self {
        SizedValue { value, size: 8 }
    }
}

#[derive(Debug, Error)]
#[error("incompatible size of {0}")]
pub struct IncompatibleRegisterSizeError(u8);
impl TryFrom<SizedValue> for RegisterValue {
    type Error = IncompatibleRegisterSizeError;

    fn try_from(value: SizedValue) -> Result<Self, Self::Error> {
        match value.size {
            1 => Ok(RegisterValue::u8(value.value as u8)),
            2 => Ok(RegisterValue::u16(value.value as u16)),
            4 => Ok(RegisterValue::u32(value.value as u32)),
            8 => Ok(RegisterValue::u64(value.value as u64)),
            16 => Ok(RegisterValue::u128(value.value)),
            _ => Err(IncompatibleRegisterSizeError(value.size)),
        }
    }
}

#[derive(Debug, Error)]
#[error("RegisterValue not convertible to SizedValue")]
pub struct ValueNotConvertible(RegisterValue);
impl TryFrom<RegisterValue> for SizedValue {
    type Error = ValueNotConvertible;

    fn try_from(value: RegisterValue) -> Result<Self, Self::Error> {
        match value {
            RegisterValue::u8(value) => Ok(SizedValue::from_u128(value as u128, 1)),
            RegisterValue::u16(value) => Ok(SizedValue::from_u128(value as u128, 2)),
            RegisterValue::u32(value) => Ok(SizedValue::from_u128(value as u128, 4)),
            RegisterValue::u40(value) => Ok(SizedValue::from_u128(value.as_u128(), 5)),
            RegisterValue::u64(value) => Ok(SizedValue::from_u128(value as u128, 8)),
            RegisterValue::u128(value) => Ok(SizedValue::from_u128(value, 16)),
            RegisterValue::ArmSpecial(SpecialArmRegisterValues::CoProcessor(value)) => {
                Ok(SizedValue::from_u128(value.value as u128, 4))
            }
            _ => Err(ValueNotConvertible(value)),
        }
    }
}

impl SizedValue {
    pub fn from_u64(value: u64, size: u8) -> Self {
        Self::from_u128(value as u128, size)
    }

    pub fn from_u128(value: u128, size: u8) -> Self {
        if size > 16 {
            panic!("SizedValue only supports sizes up to 16 bytes");
        }
        let value = value & mask(size);

        Self { value, size }
    }

    pub fn from_f64(value: f64, size: u8) -> Self {
        if size > 8 {
            panic!("SizedValue only supports sizes up to 8 bytes");
        }
        let value = match size {
            2 => f16::from_f64(value).to_bits() as u128,
            4 => (value as f32).to_bits() as u128,
            8 => value.to_bits() as u128,
            _ => panic!("only 2,4,8 byte floats are allowed"),
        };

        Self { value, size }
    }

    pub fn from_le_bytes(bytes: &[u8]) -> Self {
        if bytes.len() > SizedValue::SIZE_BYTES {
            panic!(
                "SizedValue only supports sizes up to {}",
                SizedValue::SIZE_BYTES
            );
        }

        let mut u128_buf = [0u8; SizedValue::SIZE_BYTES];
        u128_buf[0..bytes.len()].copy_from_slice(bytes);
        SizedValue {
            value: u128::from_le_bytes(u128_buf),
            size: bytes.len() as u8,
        }
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        if bytes.len() > SizedValue::SIZE_BYTES {
            panic!(
                "SizedValue only supports sizes up to {}",
                SizedValue::SIZE_BYTES
            );
        }

        let mut u128_buf = [0u8; SizedValue::SIZE_BYTES];
        u128_buf[SizedValue::SIZE_BYTES - bytes.len()..].copy_from_slice(bytes);
        SizedValue {
            value: u128::from_be_bytes(u128_buf),
            size: bytes.len() as u8,
        }
    }
    pub fn to_u64(self) -> Option<u64> {
        if self.size <= 8 {
            Some(self.value as u64)
        } else {
            None
        }
    }
    pub fn to_u128(self) -> Option<u128> {
        if self.size <= 16 {
            Some(self.value)
        } else {
            None
        }
    }

    pub fn to_f16(self) -> Option<f16> {
        if self.size == 2 {
            Some(f16::from_bits(self.value as u16))
        } else {
            None
        }
    }

    pub fn to_f32(self) -> Option<f32> {
        match self.size {
            2 => Some(f16::from_bits(self.value as u16).to_f32()),
            4 => Some(f32::from_bits(self.value as u32)),
            _ => None,
        }
    }

    pub fn to_f64(self) -> Option<f64> {
        match self.size {
            2 => Some(f16::from_bits(self.value as u16).to_f64()),
            4 => Some(f32::from_bits(self.value as u32) as f64),
            8 => Some(f64::from_bits(self.value as u64)),
            _ => None,
        }
    }

    /// Size of value in bytes.
    pub fn size(&self) -> u8 {
        self.size
    }

    pub fn to_le_bytes_alloc(self) -> Box<[u8]> {
        let size = self.size as usize;
        let mut bytes: Box<[u8]> = vec![0; size].into();
        let capped_size = SizedValue::SIZE_BYTES.min(size);
        bytes[0..capped_size].copy_from_slice(&self.value.to_le_bytes()[0..capped_size]);
        bytes
    }

    pub fn to_le_bytes(self, bytes: &mut [u8; SizedValue::SIZE_BYTES]) -> &mut [u8] {
        let size = self.size as usize;
        let capped_size = SizedValue::SIZE_BYTES.min(size);
        bytes[0..capped_size].copy_from_slice(&self.value.to_le_bytes()[0..capped_size]);
        &mut bytes[0..capped_size]
    }

    pub fn to_be_bytes_alloc(self) -> Box<[u8]> {
        let size = self.size as usize;
        let mut bytes: Box<[u8]> = vec![0; size].into();
        let capped_size = SizedValue::SIZE_BYTES.min(size);
        bytes[size - capped_size..size]
            .copy_from_slice(&self.value.to_be_bytes()[SizedValue::SIZE_BYTES - capped_size..]);

        bytes
    }

    pub fn to_be_bytes(self, bytes: &mut [u8; SizedValue::SIZE_BYTES]) -> &mut [u8] {
        let size = self.size as usize;
        let capped_size = SizedValue::SIZE_BYTES.min(size);
        bytes[size - capped_size..size]
            .copy_from_slice(&self.value.to_be_bytes()[SizedValue::SIZE_BYTES - capped_size..]);

        &mut bytes[0..capped_size]
    }

    pub fn to_bytes(self, endian: ArchEndian) -> Box<[u8]> {
        match endian {
            ArchEndian::LittleEndian => self.to_le_bytes_alloc(),
            ArchEndian::BigEndian => self.to_be_bytes_alloc(),
        }
    }

    pub fn from_bytes(bytes: &[u8], endian: ArchEndian) -> Self {
        match endian {
            ArchEndian::LittleEndian => Self::from_le_bytes(bytes),
            ArchEndian::BigEndian => Self::from_be_bytes(bytes),
        }
    }

    /// Resizes value, masking value if new size is less than previous.
    #[must_use]
    pub fn resize(mut self, new_size: u8) -> SizedValue {
        self.size = new_size;
        self.value &= u128::MAX >> (SizedValue::SIZE_BITS - 8 * new_size as usize);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::SizedValue;

    #[test]
    fn test_big_endian() {
        let value = SizedValue::from_u128(133777, 8);
        assert_eq!(value.to_be_bytes_alloc(), 133777u64.to_be_bytes().into());
    }

    #[test]
    fn test_to_be_bytes() {
        let value = SizedValue::from_u128(0x133777, 4);
        let alloc_bytes = value.to_be_bytes_alloc();
        let mut buf = [0u8; 16];
        let copy_bytes = value.to_be_bytes(&mut buf);
        let expected_bytes = &[0x00, 0x13, 0x37, 0x77];

        assert_eq!(alloc_bytes.as_ref(), copy_bytes);
        assert_eq!(copy_bytes, expected_bytes);
    }

    #[test]
    fn test_to_le_bytes() {
        let value = SizedValue::from_u128(0x133777, 4);
        let alloc_bytes = value.to_le_bytes_alloc();
        let mut buf = [0u8; 16];
        let copy_bytes = value.to_le_bytes(&mut buf);
        let expected_bytes = &[0x77, 0x37, 0x13, 0x00];

        assert_eq!(alloc_bytes.as_ref(), copy_bytes);
        assert_eq!(copy_bytes, expected_bytes);
    }

    #[test]
    fn test_resize() {
        let value = SizedValue::from_u128(0x10, 1);
        assert_eq!(value.to_u128().unwrap(), 0x10);
        let value = value.resize(2);
        assert_eq!(value.to_u128().unwrap(), 0x10);

        let value = SizedValue::from_u128(0x1337, 2);
        assert_eq!(value.to_u128().unwrap(), 0x1337);
        let value = value.resize(1);
        assert_eq!(value.to_u128().unwrap(), 0x37);
    }
}
