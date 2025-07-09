// SPDX-License-Identifier: BSD-2-Clause
use super::memory::sized_value::SizedValue;
use std::fmt::Debug;

pub trait PcodeType: Into<SizedValue> + From<SizedValue> + Debug + Clone + Copy {
    type RustType;

    fn size(&self) -> u8;

    fn value(&self) -> Self::RustType;
}

/// Floating point pcode type.
///
/// For now this can be implemented using IEEE 754 but technically must be defined by the cpu.
#[derive(Clone, Copy)]
pub struct Float {
    value: SizedValue,
}

impl PcodeType for Float {
    type RustType = f64;

    fn size(&self) -> u8 {
        self.value.size()
    }

    fn value(&self) -> Self::RustType {
        self.value.to_f64().unwrap()
    }
}

impl From<SizedValue> for Float {
    fn from(value: SizedValue) -> Self {
        if value.size() == 4 || value.size() == 8 {
            Self { value }
        } else {
            panic!("size of float must be 4 or 8 (found {})", value.size());
        }
    }
}

impl From<Float> for SizedValue {
    fn from(value: Float) -> Self {
        value.value
    }
}

impl Debug for Float {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Float({})", self.value())
    }
}

/// Unsigned integer pcode type.
#[derive(Clone, Copy)]
pub struct Int {
    value: SizedValue,
}

impl PcodeType for Int {
    type RustType = u128;

    fn size(&self) -> u8 {
        self.value.size()
    }

    fn value(&self) -> Self::RustType {
        self.value.to_u128().unwrap()
    }
}

impl From<SizedValue> for Int {
    fn from(value: SizedValue) -> Self {
        if value.size() <= SizedValue::SIZE_BYTES as u8 {
            Self { value }
        } else {
            panic!("size of int must <= 8 (found {})", value.size());
        }
    }
}

impl From<Int> for SizedValue {
    fn from(value: Int) -> Self {
        value.value
    }
}

impl Debug for Int {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Int({:?})", self.value)
    }
}

/// Signed integer pcode type.
#[derive(Clone, Copy)]
pub struct SInt {
    value: SizedValue,
}

impl PcodeType for SInt {
    type RustType = i128;

    fn size(&self) -> u8 {
        self.value.size()
    }

    fn value(&self) -> Self::RustType {
        let size_bits = self.value.size() * 8;
        let left_shift = u128::BITS - size_bits as u32;
        (self.value.to_u128().unwrap() << left_shift) as i128 >> left_shift
    }
}

impl From<SizedValue> for SInt {
    fn from(value: SizedValue) -> Self {
        if value.size() <= SizedValue::SIZE_BYTES as u8 {
            Self { value }
        } else {
            panic!("size of sint must <= 8 (found {})", value.size());
        }
    }
}

impl From<SInt> for SizedValue {
    fn from(value: SInt) -> Self {
        value.value
    }
}

impl Debug for SInt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SInt({})", self.value())
    }
}

#[derive(Clone, Copy)]
pub struct Bool(pub bool);

impl PcodeType for Bool {
    type RustType = bool;

    fn size(&self) -> u8 {
        1
    }

    fn value(&self) -> bool {
        self.0
    }
}

impl From<SizedValue> for Bool {
    fn from(value: SizedValue) -> Self {
        if value.size() == 1 {
            Self(value.to_u128().unwrap() > 0)
        } else {
            panic!("size of bool must 1 (found {})", value.size());
        }
    }
}

impl From<Bool> for SizedValue {
    fn from(value: Bool) -> Self {
        // In Rust, bool is guaranteed to be 1 or 0
        SizedValue::from_u128(value.0.into(), 1)
    }
}

impl From<bool> for Bool {
    fn from(value: bool) -> Self {
        Self(value)
    }
}

pub const FALSE: Bool = Bool(false);

impl Debug for Bool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bool({})", self.value())
    }
}
