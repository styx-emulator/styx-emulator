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
//! Architecture interfaces and definition for all target
//! platforms supported by styx irrespective of backend
//! instruction emulation engine.
//!
//! This crate defines computer architecture families as `architectures`,
//! and house them in a top-level enum [`Arch`]. Each member of that cpu
//! architecture familiy is referred to as an [`ArchitectureVariant`],
//! which is defined in the architecture specific module under [`arch`](crate::arch).
//!
//! ## Users
//!
//! Users should stay away from any type with `Meta` in the name, as those
//! are syntactic glue for instruction emulation backends (see [`Backends`](#backends)).
//!
//! The important structs and enums to use are:
//!
//! | Item | Use-case|
//! |--|--|
//! | [`ArchEndian`] | Used to specify endianness of a target architecture (for creation or querying) |
//! | [`Arch`] | Lists the available target architectures  |
//! | [`CpuRegister`] | Meta type that give details of registers you can get from the architecture + architecture variant specific lists of registers |
//! | [`ArchitectureDef`] | Used to describe a particular member of a cpu architecture family |
//!
//! combined, these allow you to create an emulator like:
//!
//! (note the use of `styx_cpu` in the examples below, ideally you do not need to import
//! `styx_cpu_type` directly).
//!
//! ```ignore
//! use styx_cpu::CpuBackend;
//! use styx_cpu::{Arch, ArchEndian, arch::arm::ArmVariants, Backend};
//!
//! let cortexm4 = CpuBackend::new(
//!     Arch::Arm,
//!     ArchEndian::LittleEndian,
//!     ArmVariants::ArmCortexM4,
//!     Backend::Unicorn,
//! );
//! ```
//!
//! ## Backends
//!
//! Parts of this crate that are necessary to use for backends are:
//!
//! | Item | Use-case |
//! |--|--|
//! | [`crate::arch::backends::ArchVariant`] | All [`ArchitectureVariant`]'s are sub-variant's of this global meta enum, when a user provides an architecture specific variant, this allows backends to match on architectures first, then perform a match on the architecture-specific `<Arch>MetaVariant` enum |
//! | [`crate::arch::backends::ArchRegister`] | This performs a role similar to above -- except for [`CpuRegister`]'s, which enables easier consumption of user proivded register identifiers |
//!
//! This allows for parsing of registers and variants like:
//!
//! ```ignore
//! # use styx_cpu_type as styx_cpu;
//! use styx_cpu::arch::backends::{ArchVariant, ArchRegister, BasicArchRegister};
//!
//! fn parse_register(reg: impl Into<ArchRegister>) {
//!     match reg.into() {
//!         ArchRegister::Basic(BasicArchRegister::Arm(inner)) => { match inner { _ => { println!("Got reg"); }} },
//!         _ => {},
//!     }
//! }
//!
//! fn parse_variant(variant: impl Into<ArchVariant>) {
//!     match variant.into() {
//!         ArchVariant::Arm(inner) => { match inner { _ => { println!("got arm variant"); }} },
//!         _ => {}
//!     }
//! }
//!
//! ```
#![allow(rustdoc::private_intra_doc_links)]
pub use arbitrary_int::{u1, u20, u4, u40, u80, TryNewError as TryNewIntError};
use derive_more::Display;
use enum_as_inner::EnumAsInner;
use enum_dispatch::enum_dispatch;
use log::warn;
use std::num::NonZeroUsize;
use std::str::FromStr;
use thiserror::Error;

// import the architectures
pub mod aarch64;
pub mod arm;
pub mod blackfin;
pub mod hexagon;
pub mod mips32;
pub mod mips64;
pub mod msp430;
pub mod ppc32;
pub mod superh;

// need to explicitly use these (since that is all that is required
// by anything consuming this), but also for `enum_dispatch`, it needs
// the items implementing the [`Architecture`] placeholder trait to be
// explicitly in-scope.
use aarch64::{variants::*, Aarch64MetaVariants, Aarch64Register, SpecialAarch64Register};
use arm::{variants::*, ArmMetaVariants, ArmRegister, SpecialArmRegister};
use blackfin::{variants::*, BlackfinMetaVariants, BlackfinRegister, SpecialBlackfinRegister};
use hexagon::{variants::*, HexagonRegister, SpecialHexagonRegister};
use mips32::{variants::*, Mips32MetaVariants, Mips32Register, SpecialMips32Register};
use mips64::{variants::*, Mips64MetaVariants, Mips64Register, SpecialMips64Register};
use msp430::{
    variants::*, Msp430MetaVariants, Msp430Register, Msp430XRegister, SpecialMsp430Register,
    SpecialMsp430XRegister,
};
use ppc32::{variants::*, Ppc32MetaVariants, Ppc32Register, SpecialPpc32Register};
use superh::{variants::*, SpecialSuperHRegister, SuperHMetaVariants, SuperHRegister};

/// Enum used for endianness selection of target cpu emulation
#[derive(Debug, Display, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum ArchEndian {
    LittleEndian = 0,
    BigEndian,
}

impl ArchEndian {
    pub fn is_big(self) -> bool {
        self == ArchEndian::BigEndian
    }

    pub fn is_little(self) -> bool {
        self == ArchEndian::LittleEndian
    }
}

#[derive(Debug, Error)]
pub enum StyxCpuArchError {
    #[error("Unable to convert {0} to {1}")]
    BadConversion(String, String),
    #[error("Bit size {0} is invalid for RegisterValue")]
    BitSizeInvalid(usize),
    #[error("Architecture `{0}` does not support `{1}`")]
    InvalidArchEndian(Arch, ArchEndian),
    #[error("Architecture `{0}` is not supported")]
    NotSupported(Arch),
    #[error("Arch: `{0}` is not supported on backend `{1}`")]
    NotSupportedArchOnBackend(Arch, crate::Backend),
    #[error("Variant: `{0:?}` is not supported on backend `{1}`")]
    NotSupportedVariantOnBackend(backends::ArchVariant, crate::Backend),
    #[error("Expected `{0}`, got `{1}`")]
    UnmatchingArchitecture(Arch, Arch),
    #[error("Architecture `{0}` does not support `{1}`")]
    UnsupportedArchModel(Arch, String),
}

/// An enum that represents possible register values
///
/// This enables a nice error checked generic implementation that allows
/// interfaces to deal with one type and one type only, while still
/// providing an easy to use interface for consumers and developers.
///
/// # Details + docs
/// This enum manually implments `PartialOrd`, `Ord`, `PartialEq`, and `Eq`
/// to ensure that the enum can be compared and sorted based on the discriminant
/// alone. Meaning that the actual value contained in the registers has no bearing
/// on the comparision of the register classes themselves.
///
/// To compare the actual values of registers, compare the values directly after
/// extracing the values from the enum with the proper getters exposed via [`EnumAsInner`]
///
/// # Implementation notes
///
/// [`PartialEq`], [`Eq`], [`PartialOrd`], and [`Ord`] are implemented for
/// this type. note that all of these implementations are strictly using
/// the discriminant, not the actual values, and that the ordering of the
/// discrimininants in the enum declaration is what determines the sort
/// [`Ordering`](std::cmp::Ordering). As this type and the architecture-specific
/// special enums are extended, *do not* forget to update the orderings if applicable.
///
/// Rust Playground [here](https://play.rust-lang.org/?version=stable&mode=debug&edition=2018&gist=cba301783a5a7f4f62968bf2945d0e39).
///
/// # Developer notes
///
/// As new types are added to this enum, do not forget to add an
/// `impl From<type> for RegisterValue` near the definition for
/// the new type, don't add it in this file, that just pollutes things.
///
/// Additionally, if the custom type requires input context in order to
/// correctly perform a read/write operation, ensure that the new type
/// also implements [`From< custom type> for crate::arch::backends::ArchRegister`]
/// so that the type can be used as the register enum selector to the
/// backend (see [`arm::SpecialArmRegisterValues`] as an
/// example).
///
/// # Backend notes
/// `CpuEngine` backends should ensure that
/// the arcitecture is correct and return approariate error when the current
/// target architecture or architecture variant is not correct.
#[allow(non_camel_case_types)]
#[derive(Debug, Eq, Clone, Copy, EnumAsInner, Display)]
pub enum RegisterValue {
    u8(u8),
    u16(u16),
    u20(u20),
    u32(u32),
    u40(u40),
    u64(u64),
    u80(u80),
    u128(u128),
    //
    // Begin architecture specific "special" registers
    //
    /// ARM special registers, only valid in a context where the
    /// currently executing target program is ARM
    ArmSpecial(arm::SpecialArmRegisterValues),
    /// PPC32 special registers, only valid in a context where the
    /// currently executing target program is PPC32
    Ppc32Special(ppc32::SpecialPpc32RegisterValues),
}

#[derive(Error, Debug)]
#[error("bad")]
pub struct ToU64Error;
impl RegisterValue {
    pub fn try_to_u64(self) -> Result<u64, ToU64Error> {
        self.to_u64().ok_or(ToU64Error)
    }

    pub fn to_u64(self) -> Option<u64> {
        match self {
            RegisterValue::u8(value) => Some(value as u64),
            RegisterValue::u16(value) => Some(value as u64),
            RegisterValue::u32(value) => Some(value as u64),
            RegisterValue::u64(value) => Some(value),
            _ => None,
        }
    }
}

pub trait RegisterValueCompatible: Default + Into<RegisterValue> {
    type ReturnValue;

    fn as_inner_value(reg_val: RegisterValue) -> Result<Self::ReturnValue, RegisterValue>;
}

impl RegisterValueCompatible for u8 {
    type ReturnValue = u8;

    fn as_inner_value(reg_val: RegisterValue) -> Result<Self::ReturnValue, RegisterValue> {
        reg_val.into_u8()
    }
}

impl RegisterValueCompatible for u16 {
    type ReturnValue = u16;

    fn as_inner_value(reg_val: RegisterValue) -> Result<Self::ReturnValue, RegisterValue> {
        reg_val.into_u16()
    }
}

impl RegisterValueCompatible for u20 {
    type ReturnValue = u20;

    fn as_inner_value(reg_val: RegisterValue) -> Result<Self::ReturnValue, RegisterValue> {
        reg_val.into_u20()
    }
}

impl RegisterValueCompatible for u32 {
    type ReturnValue = u32;

    fn as_inner_value(reg_val: RegisterValue) -> Result<Self::ReturnValue, RegisterValue> {
        reg_val.into_u32()
    }
}

impl RegisterValueCompatible for u40 {
    type ReturnValue = u40;

    fn as_inner_value(reg_val: RegisterValue) -> Result<Self::ReturnValue, RegisterValue> {
        reg_val.into_u40()
    }
}

impl RegisterValueCompatible for u64 {
    type ReturnValue = u64;

    fn as_inner_value(reg_val: RegisterValue) -> Result<Self::ReturnValue, RegisterValue> {
        reg_val.into_u64()
    }
}

impl RegisterValueCompatible for u80 {
    type ReturnValue = u80;

    fn as_inner_value(reg_val: RegisterValue) -> Result<Self::ReturnValue, RegisterValue> {
        reg_val.into_u80()
    }
}

impl RegisterValueCompatible for u128 {
    type ReturnValue = u128;

    fn as_inner_value(reg_val: RegisterValue) -> Result<Self::ReturnValue, RegisterValue> {
        reg_val.into_u128()
    }
}

impl RegisterValue {
    /// Returns an empty [`RegisterValue`] of the desired bit size useful
    /// for comparisons and size checking
    ///
    /// # NOTE
    ///
    /// This method will not let you obtain architecture specific special
    /// register types eg [`RegisterValue::ArmSpecial`], only the unsigned
    /// primitive types
    pub const fn from_bit_size(bit_size: usize) -> Self {
        match bit_size {
            8 => Self::u8(0),
            16 => Self::u16(0),
            20 => Self::u20(u20::new(0)),
            32 => Self::u32(0),
            40 => Self::u40(u40::new(0)),
            64 => Self::u64(0),
            80 => Self::u80(u80::new(0)),
            128 => Self::u128(0),
            _ => panic!("Bad bit size"),
        }
    }

    // Number of bits this register is sized as.
    pub const fn to_bit_size(self) -> usize {
        match self {
            RegisterValue::u8(_) => 8,
            RegisterValue::u16(_) => 16,
            RegisterValue::u20(_) => 20,
            RegisterValue::u32(_) => 32,
            RegisterValue::u40(_) => 40,
            RegisterValue::u64(_) => 64,
            RegisterValue::u80(_) => 80,
            RegisterValue::u128(_) => 128,
            RegisterValue::ArmSpecial(_) => 32,
            RegisterValue::Ppc32Special(_) => 32,
        }
    }

    /// Number of bytes this register is sized as.
    pub const fn to_byte_size(self) -> usize {
        match self {
            RegisterValue::u8(_) => 1,
            RegisterValue::u16(_) => 2,
            RegisterValue::u20(_) => todo!(),
            RegisterValue::u32(_) => 4,
            RegisterValue::u40(_) => 5,
            RegisterValue::u64(_) => 8,
            RegisterValue::u80(_) => 10,
            RegisterValue::u128(_) => 16,
            RegisterValue::ArmSpecial(_) => 4,
            RegisterValue::Ppc32Special(_) => 4,
        }
    }
}

// the eq is based on the discriminant, not the value
impl PartialEq for RegisterValue {
    fn eq(&self, other: &Self) -> bool {
        core::mem::discriminant(self) == core::mem::discriminant(other)
    }
}

impl PartialOrd for RegisterValue {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RegisterValue {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // if the discriminants are equal, return equal
        //
        // unless of course, this is a special register, in which case
        // recurse into the special register to check against itself
        if self == other {
            // All arch specific "special" registers must
            // recurse 1 level to check against themselves here
            return match self {
                RegisterValue::ArmSpecial(self_val) => {
                    self_val.cmp(other.as_arm_special().unwrap())
                }
                RegisterValue::Ppc32Special(self_val) => {
                    self_val.cmp(other.as_ppc32_special().unwrap())
                }
                // here we be explicit instead of a wildcard so that
                // any future editions emit a compile error instead of causing
                // a many-hour-debug-head-scratching-moment
                RegisterValue::u8(_)
                | RegisterValue::u16(_)
                | RegisterValue::u20(_)
                | RegisterValue::u32(_)
                | RegisterValue::u40(_)
                | RegisterValue::u64(_)
                | RegisterValue::u80(_)
                | RegisterValue::u128(_) => std::cmp::Ordering::Equal,
            };
        }

        //
        // past this we know that self != other
        //
        debug_assert_ne!(self, other);

        match self {
            //
            // Special cases begin here, remember that they recurse into themselves
            // when `self = other` as checked at the begininng of this method
            //
            RegisterValue::Ppc32Special(_) => {
                // Ppc32Special is larger than u8, u16, u32, u40, u64, u80, u128,
                // and ArmSpecial, but smaller than everything else
                match other {
                    RegisterValue::u8(_)
                    | RegisterValue::u16(_)
                    | RegisterValue::u20(_)
                    | RegisterValue::u32(_)
                    | RegisterValue::u40(_)
                    | RegisterValue::u64(_)
                    | RegisterValue::u80(_)
                    | RegisterValue::u128(_)
                    | RegisterValue::ArmSpecial(_) => std::cmp::Ordering::Greater,
                    _ => std::cmp::Ordering::Less,
                }
            }
            RegisterValue::ArmSpecial(_) => {
                // ArmSpecial is larger than u8, u16, u32, u40, u64, u80, u128,
                // and smaller than everything else
                match other {
                    RegisterValue::u8(_)
                    | RegisterValue::u16(_)
                    | RegisterValue::u20(_)
                    | RegisterValue::u32(_)
                    | RegisterValue::u40(_)
                    | RegisterValue::u64(_)
                    | RegisterValue::u80(_)
                    | RegisterValue::u128(_) => std::cmp::Ordering::Greater,
                    _ => std::cmp::Ordering::Less,
                }
            }
            _ => self.to_bit_size().cmp(&other.to_bit_size()),
        }
    }
}

#[cfg(test)]
mod register_value_conversion_tests {
    use super::*;
    use test_case::test_case;

    #[test_case(0u8, RegisterValue::u8(0); "into u8")]
    #[test_case(0u16, RegisterValue::u16(0); "into u16")]
    #[test_case(0u32, RegisterValue::u32(0); "into u32")]
    #[test_case(u40::from(0u8), RegisterValue::u40(u40::from(0u8)); "into u40")]
    #[test_case(0u64, RegisterValue::u64(0); "into u64")]
    #[test_case(u80::from(0u8), RegisterValue::u80(u80::from(0u8)); "into u80")]
    #[test_case(0u128, RegisterValue::u128(0); "into u128")]
    fn test_simple_into(value: impl Into<RegisterValue>, output: RegisterValue) {
        // make sure, given the same bottom level values, we can convert different
        // integer types into the enum

        assert_eq!(output, value.into());
    }

    #[test_case(0u8, 0u8; "u8 same value")]
    #[test_case(0u8, 1u8; "u8 diff value")]
    #[test_case(0u16, 0u16; "u16 same value")]
    #[test_case(0u16, 1u16; "u16 diff value")]
    #[test_case(0u32, 0u32; "u32 same value")]
    #[test_case(0u32, 1u32; "u32 diff value")]
    #[test_case(u40::from(0u8), u40::from(0u8); "u40 same value")]
    #[test_case(u40::from(0u8), u40::from(1u8); "u40 diff value")]
    #[test_case(0u64, 0u64; "u64 same value")]
    #[test_case(0u64, 1u64; "u64 diff value")]
    #[test_case(u80::from(0u8), u80::from(0u8); "u80 same value")]
    #[test_case(u80::from(0u8), u80::from(1u8); "u80 diff value")]
    #[test_case(0u128, 0u128; "u128 same value")]
    #[test_case(0u128, 1u128; "u128 diff value")]
    fn test_eq<T: Into<RegisterValue>>(a: T, b: T) {
        // make sure that the discriminants are equal to their discriminants
        // with the same, and with different values
        assert_eq!(a.into(), b.into());
    }

    #[test_case(0u8, 0u16; "u8 u16 same")]
    #[test_case(0u8, 1u16; "u8 u16 diff")]
    #[test_case(0u8, 0u32; "u8 u32 same")]
    #[test_case(0u8, 1u32; "u8 u32 diff")]
    #[test_case(0u8, u40::from(0u8); "u8 u40 same")]
    #[test_case(0u8, u40::from(1u8); "u8 u40 diff")]
    #[test_case(0u8, 0u64; "u8 u64 same")]
    #[test_case(0u8, 1u64; "u8 u64 diff")]
    #[test_case(0u8, u80::from(0u8); "u8 u80 same")]
    #[test_case(0u8, u80::from(1u8); "u8 u80 diff")]
    #[test_case(0u8, 0u128; "u8 u128 same")]
    #[test_case(0u8, 1u128; "u8 u128 diff")]
    // doing any more as the base type is pretty pointless
    fn test_ne<T: Into<RegisterValue>, Y: Into<RegisterValue>>(a: T, b: Y) {
        // make sure that the discriminants are not equal to other discriminants
        // with the same, and with different values
        assert_ne!(a.into(), b.into());
    }

    #[test_case(0u8, 0u8, std::cmp::Ordering::Equal; "u8 cmp equal u8")]
    #[test_case(0u8, 0u16, std::cmp::Ordering::Less; "u8 cmp equal u16")]
    #[test_case(0u8, 0u32, std::cmp::Ordering::Less; "u8 cmp equal u32")]
    #[test_case(0u8, u40::from(0u8), std::cmp::Ordering::Less; "u8 cmp equal u40")]
    #[test_case(0u8, 0u64, std::cmp::Ordering::Less; "u8 cmp equal u64")]
    #[test_case(0u8, u80::from(0u8), std::cmp::Ordering::Less; "u8 cmp equal u80")]
    #[test_case(0u8, 0u128, std::cmp::Ordering::Less; "u8 cmp equal u128")]
    #[test_case(0u16, 0u8, std::cmp::Ordering::Greater; "u16 cmp equal u8")]
    #[test_case(0u16, 0u16, std::cmp::Ordering::Equal; "u16 cmp equal u16")]
    #[test_case(0u16, 0u32, std::cmp::Ordering::Less; "u16 cmp equal u32")]
    #[test_case(0u16, u40::from(0u8), std::cmp::Ordering::Less; "u16 cmp equal u40")]
    #[test_case(0u16, 0u64, std::cmp::Ordering::Less; "u16 cmp equal u64")]
    #[test_case(0u16, u80::from(0u8), std::cmp::Ordering::Less; "u16 cmp equal u80")]
    #[test_case(0u16, 0u128, std::cmp::Ordering::Less; "u16 cmp equal u128")]
    #[test_case(0u32, 0u8, std::cmp::Ordering::Greater; "u32 cmp equal u8")]
    #[test_case(0u32, 0u16, std::cmp::Ordering::Greater; "u32 cmp equal u16")]
    #[test_case(0u32, 0u32, std::cmp::Ordering::Equal; "u32 cmp equal u32")]
    #[test_case(0u32, u40::from(0u8), std::cmp::Ordering::Less; "u32 cmp equal u40")]
    #[test_case(0u32, 0u64, std::cmp::Ordering::Less; "u32 cmp equal u64")]
    #[test_case(0u32, u80::from(0u8), std::cmp::Ordering::Less; "u32 cmp equal u80")]
    #[test_case(0u32, 0u128, std::cmp::Ordering::Less; "u32 cmp equal u128")]
    #[test_case(u40::from(0u8), 0u8, std::cmp::Ordering::Greater; "u40 cmp equal u8")]
    #[test_case(u40::from(0u8), 0u16, std::cmp::Ordering::Greater; "u40 cmp equal u16")]
    #[test_case(u40::from(0u8), 0u32, std::cmp::Ordering::Greater; "u40 cmp equal u32")]
    #[test_case(u40::from(0u8), u40::from(0u8), std::cmp::Ordering::Equal; "u40 cmp equal u40")]
    #[test_case(u40::from(0u8), 0u64, std::cmp::Ordering::Less; "u40 cmp equal u64")]
    #[test_case(u40::from(0u8), u80::from(0u8), std::cmp::Ordering::Less; "u40 cmp equal u80")]
    #[test_case(u40::from(0u8), 0u128, std::cmp::Ordering::Less; "u40 cmp equal u128")]
    #[test_case(0u64, 0u8, std::cmp::Ordering::Greater; "u64 cmp equal u8")]
    #[test_case(0u64, 0u16, std::cmp::Ordering::Greater; "u64 cmp equal u16")]
    #[test_case(0u64, 0u32, std::cmp::Ordering::Greater; "u64 cmp equal u32")]
    #[test_case(0u64, u40::from(0u8), std::cmp::Ordering::Greater; "u64 cmp equal u40")]
    #[test_case(0u64, 0u64, std::cmp::Ordering::Equal; "u64 cmp equal u64")]
    #[test_case(0u64, u80::from(0u8), std::cmp::Ordering::Less; "u64 cmp equal u80")]
    #[test_case(0u64, 0u128, std::cmp::Ordering::Less; "u64 cmp equal u128")]
    #[test_case(u80::from(0u8), 0u8, std::cmp::Ordering::Greater; "u80 cmp equal u8")]
    #[test_case(u80::from(0u8), 0u16, std::cmp::Ordering::Greater; "u80 cmp equal u16")]
    #[test_case(u80::from(0u8), 0u32, std::cmp::Ordering::Greater; "u80 cmp equal u32")]
    #[test_case(u80::from(0u8), u40::from(0u8), std::cmp::Ordering::Greater; "u80 cmp equal u40")]
    #[test_case(u80::from(0u8), 0u64, std::cmp::Ordering::Greater; "u80 cmp equal u64")]
    #[test_case(u80::from(0u8), u80::from(0u8), std::cmp::Ordering::Equal; "u80 cmp equal u80")]
    #[test_case(u80::from(0u8), 0u128, std::cmp::Ordering::Less; "u80 cmp equal u128")]
    #[test_case(0u128, 0u8, std::cmp::Ordering::Greater; "u128 cmp equal u8")]
    #[test_case(0u128, 0u16, std::cmp::Ordering::Greater; "u128 cmp equal u16")]
    #[test_case(0u128, 0u32, std::cmp::Ordering::Greater; "u128 cmp equal u32")]
    #[test_case(0u128, u40::from(0u8), std::cmp::Ordering::Greater; "u128 cmp equal u40")]
    #[test_case(0u128, 0u64, std::cmp::Ordering::Greater; "u128 cmp equal u64")]
    #[test_case(0u128, u80::from(0u8), std::cmp::Ordering::Greater; "u128 cmp equal u80")]
    #[test_case(0u128, 0u128, std::cmp::Ordering::Equal; "u128 cmp equal u128")]
    #[test_case(1u8, 0u8, std::cmp::Ordering::Equal; "u8 cmp smaller u8")]
    #[test_case(1u8, 0u16, std::cmp::Ordering::Less; "u8 cmp smaller u16")]
    #[test_case(1u8, 0u32, std::cmp::Ordering::Less; "u8 cmp smaller u32")]
    #[test_case(1u8, u40::from(0u8), std::cmp::Ordering::Less; "u8 cmp smaller u40")]
    #[test_case(1u8, 0u64, std::cmp::Ordering::Less; "u8 cmp smaller u64")]
    #[test_case(1u8, u80::from(0u8), std::cmp::Ordering::Less; "u8 cmp smaller u80")]
    #[test_case(1u8, 0u128, std::cmp::Ordering::Less; "u8 cmp smaller u128")]
    #[test_case(1u16, 0u8, std::cmp::Ordering::Greater; "u16 cmp smaller u8")]
    #[test_case(1u16, 0u16, std::cmp::Ordering::Equal; "u16 cmp smaller u16")]
    #[test_case(1u16, 0u32, std::cmp::Ordering::Less; "u16 cmp smaller u32")]
    #[test_case(1u16, u40::from(0u8), std::cmp::Ordering::Less; "u16 cmp smaller u40")]
    #[test_case(1u16, 0u64, std::cmp::Ordering::Less; "u16 cmp smaller u64")]
    #[test_case(1u16, u80::from(0u8), std::cmp::Ordering::Less; "u16 cmp smaller u80")]
    #[test_case(1u16, 0u128, std::cmp::Ordering::Less; "u16 cmp smaller u128")]
    #[test_case(1u32, 0u8, std::cmp::Ordering::Greater; "u32 cmp smaller u8")]
    #[test_case(1u32, 0u16, std::cmp::Ordering::Greater; "u32 cmp smaller u16")]
    #[test_case(1u32, 0u32, std::cmp::Ordering::Equal; "u32 cmp smaller u32")]
    #[test_case(1u32, u40::from(0u8), std::cmp::Ordering::Less; "u32 cmp smaller u40")]
    #[test_case(1u32, 0u64, std::cmp::Ordering::Less; "u32 cmp smaller u64")]
    #[test_case(1u32, u80::from(0u8), std::cmp::Ordering::Less; "u32 cmp smaller u80")]
    #[test_case(1u32, 0u128, std::cmp::Ordering::Less; "u32 cmp smaller u128")]
    #[test_case(u40::from(1u8), 0u8, std::cmp::Ordering::Greater; "u40 cmp smaller u8")]
    #[test_case(u40::from(1u8), 0u16, std::cmp::Ordering::Greater; "u40 cmp smaller u16")]
    #[test_case(u40::from(1u8), 0u32, std::cmp::Ordering::Greater; "u40 cmp smaller u32")]
    #[test_case(u40::from(1u8), u40::from(0u8), std::cmp::Ordering::Equal; "u40 cmp smaller u40")]
    #[test_case(u40::from(1u8), 0u64, std::cmp::Ordering::Less; "u40 cmp smaller u64")]
    #[test_case(u40::from(1u8), u80::from(0u8), std::cmp::Ordering::Less; "u40 cmp smaller u80")]
    #[test_case(u40::from(1u8), 0u128, std::cmp::Ordering::Less; "u40 cmp smaller u128")]
    #[test_case(1u64, 0u8, std::cmp::Ordering::Greater; "u64 cmp smaller u8")]
    #[test_case(1u64, 0u16, std::cmp::Ordering::Greater; "u64 cmp smaller u16")]
    #[test_case(1u64, 0u32, std::cmp::Ordering::Greater; "u64 cmp smaller u32")]
    #[test_case(1u64, u40::from(0u8), std::cmp::Ordering::Greater; "u64 cmp smaller u40")]
    #[test_case(1u64, 0u64, std::cmp::Ordering::Equal; "u64 cmp smaller u64")]
    #[test_case(1u64, u80::from(0u8), std::cmp::Ordering::Less; "u64 cmp smaller u80")]
    #[test_case(1u64, 0u128, std::cmp::Ordering::Less; "u64 cmp smaller u128")]
    #[test_case(u80::from(1u8), 0u8, std::cmp::Ordering::Greater; "u80 cmp smaller u8")]
    #[test_case(u80::from(1u8), 0u16, std::cmp::Ordering::Greater; "u80 cmp smaller u16")]
    #[test_case(u80::from(1u8), 0u32, std::cmp::Ordering::Greater; "u80 cmp smaller u32")]
    #[test_case(u80::from(1u8), u40::from(0u8), std::cmp::Ordering::Greater; "u80 cmp smaller u40")]
    #[test_case(u80::from(1u8), 0u64, std::cmp::Ordering::Greater; "u80 cmp smaller u64")]
    #[test_case(u80::from(1u8), u80::from(0u8), std::cmp::Ordering::Equal; "u80 cmp smaller u80")]
    #[test_case(u80::from(1u8), 0u128, std::cmp::Ordering::Less; "u80 cmp smaller u128")]
    #[test_case(1u128, 0u8, std::cmp::Ordering::Greater; "u128 cmp smaller u8")]
    #[test_case(1u128, 0u16, std::cmp::Ordering::Greater; "u128 cmp smaller u16")]
    #[test_case(1u128, 0u32, std::cmp::Ordering::Greater; "u128 cmp smaller u32")]
    #[test_case(1u128, u40::from(0u8), std::cmp::Ordering::Greater; "u128 cmp smaller u40")]
    #[test_case(1u128, 0u64, std::cmp::Ordering::Greater; "u128 cmp smaller u64")]
    #[test_case(1u128, u80::from(0u8), std::cmp::Ordering::Greater; "u128 cmp smaller u80")]
    #[test_case(1u128, 0u128, std::cmp::Ordering::Equal; "u128 cmp smaller u128")]
    #[test_case(0u8, 1u8, std::cmp::Ordering::Equal; "u8 cmp larger u8")]
    #[test_case(0u8, 1u16, std::cmp::Ordering::Less; "u8 cmp larger u16")]
    #[test_case(0u8, 1u32, std::cmp::Ordering::Less; "u8 cmp larger u32")]
    #[test_case(0u8, u40::from(1u8), std::cmp::Ordering::Less; "u8 cmp larger u40")]
    #[test_case(0u8, 1u64, std::cmp::Ordering::Less; "u8 cmp larger u64")]
    #[test_case(0u8, u80::from(1u8), std::cmp::Ordering::Less; "u8 cmp larger u80")]
    #[test_case(0u8, 1u128, std::cmp::Ordering::Less; "u8 cmp larger u128")]
    #[test_case(0u16, 1u8, std::cmp::Ordering::Greater; "u16 cmp larger u8")]
    #[test_case(0u16, 1u16, std::cmp::Ordering::Equal; "u16 cmp larger u16")]
    #[test_case(0u16, 1u32, std::cmp::Ordering::Less; "u16 cmp larger u32")]
    #[test_case(0u16, u40::from(1u8), std::cmp::Ordering::Less; "u16 cmp larger u40")]
    #[test_case(0u16, 1u64, std::cmp::Ordering::Less; "u16 cmp larger u64")]
    #[test_case(0u16, u80::from(1u8), std::cmp::Ordering::Less; "u16 cmp larger u80")]
    #[test_case(0u16, 1u128, std::cmp::Ordering::Less; "u16 cmp larger u128")]
    #[test_case(0u32, 1u8, std::cmp::Ordering::Greater; "u32 cmp larger u8")]
    #[test_case(0u32, 1u16, std::cmp::Ordering::Greater; "u32 cmp larger u16")]
    #[test_case(0u32, 1u32, std::cmp::Ordering::Equal; "u32 cmp larger u32")]
    #[test_case(0u32, u40::from(1u8), std::cmp::Ordering::Less; "u32 cmp larger u40")]
    #[test_case(0u32, 1u64, std::cmp::Ordering::Less; "u32 cmp larger u64")]
    #[test_case(0u32, u80::from(1u8), std::cmp::Ordering::Less; "u32 cmp larger u80")]
    #[test_case(0u32, 1u128, std::cmp::Ordering::Less; "u32 cmp larger u128")]
    #[test_case(u40::from(0u8), 1u8, std::cmp::Ordering::Greater; "u40 cmp larger u8")]
    #[test_case(u40::from(0u8), 1u16, std::cmp::Ordering::Greater; "u40 cmp larger u16")]
    #[test_case(u40::from(0u8), 1u32, std::cmp::Ordering::Greater; "u40 cmp larger u32")]
    #[test_case(u40::from(0u8), u40::from(1u8), std::cmp::Ordering::Equal; "u40 cmp larger u40")]
    #[test_case(u40::from(0u8), 1u64, std::cmp::Ordering::Less; "u40 cmp larger u64")]
    #[test_case(u40::from(0u8), u80::from(1u8), std::cmp::Ordering::Less; "u40 cmp larger u80")]
    #[test_case(u40::from(0u8), 1u128, std::cmp::Ordering::Less; "u40 cmp larger u128")]
    #[test_case(0u64, 1u8, std::cmp::Ordering::Greater; "u64 cmp larger u8")]
    #[test_case(0u64, 1u16, std::cmp::Ordering::Greater; "u64 cmp larger u16")]
    #[test_case(0u64, 1u32, std::cmp::Ordering::Greater; "u64 cmp larger u32")]
    #[test_case(0u64, u40::from(1u8), std::cmp::Ordering::Greater; "u64 cmp larger u40")]
    #[test_case(0u64, 1u64, std::cmp::Ordering::Equal; "u64 cmp larger u64")]
    #[test_case(0u64, u80::from(1u8), std::cmp::Ordering::Less; "u64 cmp larger u80")]
    #[test_case(0u64, 1u128, std::cmp::Ordering::Less; "u64 cmp larger u128")]
    #[test_case(u80::from(0u8), 1u8, std::cmp::Ordering::Greater; "u80 cmp larger u8")]
    #[test_case(u80::from(0u8), 1u16, std::cmp::Ordering::Greater; "u80 cmp larger u16")]
    #[test_case(u80::from(0u8), 1u32, std::cmp::Ordering::Greater; "u80 cmp larger u32")]
    #[test_case(u80::from(0u8), u40::from(1u8), std::cmp::Ordering::Greater; "u80 cmp larger u40")]
    #[test_case(u80::from(0u8), 1u64, std::cmp::Ordering::Greater; "u80 cmp larger u64")]
    #[test_case(u80::from(0u8), u80::from(1u8), std::cmp::Ordering::Equal; "u80 cmp larger u80")]
    #[test_case(u80::from(0u8), 1u128, std::cmp::Ordering::Less; "u80 cmp larger u128")]
    #[test_case(0u128, 1u8, std::cmp::Ordering::Greater; "u128 cmp larger u8")]
    #[test_case(0u128, 1u16, std::cmp::Ordering::Greater; "u128 cmp larger u16")]
    #[test_case(0u128, 1u32, std::cmp::Ordering::Greater; "u128 cmp larger u32")]
    #[test_case(0u128, u40::from(1u8), std::cmp::Ordering::Greater; "u128 cmp larger u40")]
    #[test_case(0u128, 1u64, std::cmp::Ordering::Greater; "u128 cmp larger u64")]
    #[test_case(0u128, u80::from(1u8), std::cmp::Ordering::Greater; "u128 cmp larger u80")]
    #[test_case(0u128, 1u128, std::cmp::Ordering::Equal; "u128 cmp larger u128")]
    // this test alone has already caught a few bugs
    fn test_ordering<T: Into<RegisterValue>, Y: Into<RegisterValue>>(
        a: T,
        b: Y,
        answer: std::cmp::Ordering,
    ) {
        // ensures that the discriminant ordering invariant holds
        let a_into = a.into();
        let b_into = b.into();

        assert_eq!(answer, a_into.cmp(&b_into));
    }
}

impl From<u8> for RegisterValue {
    fn from(value: u8) -> Self {
        Self::u8(value)
    }
}

impl From<u16> for RegisterValue {
    fn from(value: u16) -> Self {
        Self::u16(value)
    }
}

impl From<u20> for RegisterValue {
    fn from(value: u20) -> Self {
        Self::u20(value)
    }
}

impl From<u32> for RegisterValue {
    fn from(value: u32) -> Self {
        Self::u32(value)
    }
}

impl From<u40> for RegisterValue {
    fn from(value: u40) -> Self {
        Self::u40(value)
    }
}

impl From<u64> for RegisterValue {
    fn from(value: u64) -> Self {
        Self::u64(value)
    }
}

impl From<u80> for RegisterValue {
    fn from(value: u80) -> Self {
        Self::u80(value)
    }
}

impl From<u128> for RegisterValue {
    fn from(value: u128) -> Self {
        Self::u128(value)
    }
}

/// The top-level C-style `Architecture` selection
#[repr(C)]
#[derive(Debug, Display, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash)]
pub enum Arch {
    Aarch64 = 0,
    Arm,
    Blackfin,
    Mips32,
    Mips64,
    X86,
    Ppc32,
    Sparc,
    M68k,
    Riscv,
    Tricore,
    Sharc,
    Microblaze,
    Tms320C1x,
    Tms320C2x,
    Tms320C3x,
    Tms320C4x,
    Tms320C8x,
    Tms320C5x,
    Tms320C6x,
    Avr,
    SuperH,
    Pic,
    Arch80xx,
    Arch6502,
    Z80,
    Xtensa,
    Hcsxx,
    V850,
    Msp430,
    Msp430X,
}

impl Arch {
    /// Returns the register used as the program counter for styx
    ///
    /// ```rust
    /// # use styx_cpu_type as styx_cpu;
    /// use styx_cpu::Arch;
    /// use styx_cpu::arch::arm::ArmRegister;
    ///
    /// let pc_reg = Arch::Arm.pc();
    /// # assert_eq!(pc_reg, ArmRegister::Pc.into(), "PC register is not correct");
    /// ```
    pub const fn pc(&self) -> backends::BasicArchRegister {
        use backends::BasicArchRegister;

        match self {
            Self::Arm => BasicArchRegister::Arm(ArmRegister::Pc),
            Self::Ppc32 => BasicArchRegister::Ppc32(Ppc32Register::Pc),
            Self::Mips32 => BasicArchRegister::Mips32(Mips32Register::Pc),
            Self::Mips64 => BasicArchRegister::Mips64(Mips64Register::Pc),
            Self::Blackfin => BasicArchRegister::Blackfin(BlackfinRegister::Pc),
            Self::SuperH => BasicArchRegister::SuperH(SuperHRegister::Pc),
            Self::Msp430 => BasicArchRegister::Msp430(Msp430Register::Pc),
            Self::Msp430X => BasicArchRegister::Msp430X(Msp430XRegister::Pc),
            _ => panic!("Need to add PC register for arch"),
        }
    }

    /// Returns the register that matches the provided string.
    ///
    /// ```rust
    /// # use styx_cpu_type as styx_cpu;
    /// use styx_cpu::Arch;
    /// use styx_cpu::arch::arm::ArmRegister;
    ///
    /// let sp_reg = Arch::Arm.get_register("sp");
    /// # assert_eq!(sp_reg, ArmRegister::Sp.into());
    /// ```
    pub fn get_register(&self, reg_name: &str) -> backends::BasicArchRegister {
        use backends::BasicArchRegister;

        match self {
            Self::Arm => BasicArchRegister::Arm(
                ArmRegister::from_str(reg_name)
                    .unwrap_or_else(|_| panic!("Unsupported register: {reg_name}")),
            ),
            Self::Ppc32 => BasicArchRegister::Ppc32(
                Ppc32Register::from_str(reg_name)
                    .unwrap_or_else(|_| panic!("Unsupported register: {reg_name}")),
            ),
            Self::Mips32 => BasicArchRegister::Mips32(
                Mips32Register::from_str(reg_name)
                    .unwrap_or_else(|_| panic!("Unsupported register: {reg_name}")),
            ),
            Self::Mips64 => BasicArchRegister::Mips64(
                Mips64Register::from_str(reg_name)
                    .unwrap_or_else(|_| panic!("Unsupported register: {reg_name}")),
            ),
            Self::Blackfin => BasicArchRegister::Blackfin(
                BlackfinRegister::from_str(reg_name)
                    .unwrap_or_else(|_| panic!("Unsupported register: {reg_name}")),
            ),
            Self::SuperH => BasicArchRegister::SuperH(
                SuperHRegister::from_str(reg_name)
                    .unwrap_or_else(|_| panic!("Unsupported register {reg_name}")),
            ),
            Self::Msp430 => BasicArchRegister::Msp430(
                Msp430Register::from_str(reg_name)
                    .unwrap_or_else(|_| panic!("Unsupported register {reg_name}")),
            ),
            _ => panic!("Unsupported architecure: {self:?}"),
        }
    }
}

/// Provides meta-enums for all cpu backends to consume from
pub mod backends {
    use super::*;

    /// The top-level register enum that all backends accept.
    ///
    /// All architectures need to have a variant dedicated to their own
    /// register enum following the naming `<Arch>Registers` eg. [`ArmRegister`]
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Display, PartialOrd, Ord, Hash)]
    pub enum BasicArchRegister {
        Arm(ArmRegister),
        Aarch64(Aarch64Register),
        Ppc32(Ppc32Register),
        Mips32(Mips32Register),
        Mips64(Mips64Register),
        Blackfin(BlackfinRegister),
        SuperH(SuperHRegister),
        Msp430(Msp430Register),
        Msp430X(Msp430XRegister),
        Hexagon(HexagonRegister),
    }

    impl BasicArchRegister {
        pub const fn register_value_enum(&self) -> RegisterValue {
            match self {
                Self::Arm(a) => a.register_value_enum(),
                Self::Aarch64(a) => a.register_value_enum(),
                Self::Ppc32(p) => p.register_value_enum(),
                Self::Mips32(p) => p.register_value_enum(),
                Self::Mips64(p) => p.register_value_enum(),
                Self::Blackfin(b) => b.register_value_enum(),
                Self::SuperH(b) => b.register_value_enum(),
                Self::Msp430(b) => b.register_value_enum(),
                Self::Msp430X(b) => b.register_value_enum(),
                Self::Hexagon(b) => b.register_value_enum(),
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Display, PartialOrd, Ord, Hash)]
    pub enum SpecialArchRegister {
        Aarch64(SpecialAarch64Register),
        Arm(SpecialArmRegister),
        Ppc32(SpecialPpc32Register),
        Mips32(SpecialMips32Register),
        Mips64(SpecialMips64Register),
        Hexagon(SpecialHexagonRegister),
        Blackfin(SpecialBlackfinRegister),
        SuperH(SpecialSuperHRegister),
        Msp430(SpecialMsp430Register),
        Msp430X(SpecialMsp430XRegister),
    }

    impl SpecialArchRegister {
        pub const fn register_value_enum(&self) -> RegisterValue {
            match self {
                SpecialArchRegister::Aarch64(reg) => reg.register_value_enum(),
                SpecialArchRegister::Arm(reg) => reg.register_value_enum(),
                SpecialArchRegister::Ppc32(reg) => reg.register_value_enum(),
                SpecialArchRegister::Mips32(reg) => reg.register_value_enum(),
                SpecialArchRegister::Mips64(reg) => reg.register_value_enum(),
                SpecialArchRegister::Blackfin(reg) => reg.register_value_enum(),
                SpecialArchRegister::SuperH(reg) => reg.register_value_enum(),
                SpecialArchRegister::Msp430(reg) => reg.register_value_enum(),
                SpecialArchRegister::Msp430X(reg) => reg.register_value_enum(),
                SpecialArchRegister::Hexagon(reg) => reg.register_value_enum(),
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Display, PartialOrd, Ord, Hash)]
    pub enum ArchRegister {
        Basic(BasicArchRegister),
        Special(SpecialArchRegister),
    }

    impl ArchRegister {
        pub const fn register_value_enum(&self) -> RegisterValue {
            match self {
                ArchRegister::Basic(reg) => reg.register_value_enum(),
                ArchRegister::Special(reg) => reg.register_value_enum(),
            }
        }
    }

    impl From<SpecialArchRegister> for ArchRegister {
        fn from(value: SpecialArchRegister) -> Self {
            Self::Special(value)
        }
    }

    impl From<BasicArchRegister> for ArchRegister {
        fn from(value: BasicArchRegister) -> Self {
            Self::Basic(value)
        }
    }

    /// The top-level architecture variant enum that all backends accept.
    ///
    /// All architectures need to have a variant dedicated to their own
    /// enum of architecture variants.
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub enum ArchVariant {
        Arm(ArmMetaVariants),
        Aarch64(Aarch64MetaVariants),
        Blackfin(BlackfinMetaVariants),
        Mips32(Mips32MetaVariants),
        Mips64(Mips64MetaVariants),
        Msp430(Msp430MetaVariants),
        Ppc32(Ppc32MetaVariants),
        SuperH(SuperHMetaVariants),
    }

    impl From<ArchVariant> for Box<dyn ArchitectureDef> {
        fn from(value: ArchVariant) -> Self {
            match value {
                ArchVariant::Arm(arm_meta) => arm_meta.into(),
                ArchVariant::Aarch64(arm64_meta) => arm64_meta.into(),
                ArchVariant::Blackfin(blackfin_meta) => blackfin_meta.into(),
                ArchVariant::Ppc32(ppc32_meta) => ppc32_meta.into(),
                ArchVariant::Mips32(mips32_meta) => mips32_meta.into(),
                ArchVariant::Mips64(mips64_meta) => mips64_meta.into(),
                ArchVariant::SuperH(superh_meta) => superh_meta.into(),
                ArchVariant::Msp430(msp430_meta) => msp430_meta.into(),
            }
        }
    }
}

/// Used to represent a cpu register, a container over the
/// bit length and name of the register, fetch through accessing the
/// architecture specific enum of registers.
#[derive(Debug, Clone)]
pub struct CpuRegister {
    /// Name of the register
    name: &'static str,

    /// Size of the register in bits
    bit_size: NonZeroUsize,

    /// Meta-register enum value, used for being
    /// consumed by a `CpuBackend`.
    reg_enum: backends::ArchRegister,

    /// The [`RegisterValue`] enum variant for this register, useful
    /// for size comparison in const and runtime contexts
    register_value: RegisterValue,
}

impl CpuRegister {
    /// Size of the register in bytes
    pub fn byte_size(&self) -> NonZeroUsize {
        (self.bit_size.get() / 8).try_into().unwrap_or_else(|_| {
            warn!(
                "Register `{}` byte size is reported as 0, using 4 as default",
                self.name()
            );
            NonZeroUsize::new(4).unwrap()
        })
    }

    pub fn register_value_enum(&self) -> RegisterValue {
        self.register_value
    }

    /// Size of the register in bits
    pub const fn bit_size(&self) -> NonZeroUsize {
        self.bit_size
    }

    /// Getter for the name of the register
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Getter for the global register enum variant
    pub const fn variant(&self) -> backends::ArchRegister {
        self.reg_enum
    }
}

/// Marker Trait, used to provide a path to traverse from
/// an architecture variant and retrieve the underlying architecure
/// descriptions.
#[enum_dispatch]
pub trait ArchitectureVariant: std::fmt::Debug + std::fmt::Display + Clone {}

/// Core Architecture trait implemented by each leaf node
/// in a cpu architecture family.
///
/// [`ArchitectureDef`] has a single mandatory associated type
/// required to implement the trait (among the required methods).
///
/// `Self::Usize` is used to set the word-size for the target
/// architecture and the default core-register size, data size,
/// and instruction word size as some architectures vary wildly
/// in size alignment. While all the specific sizes can default to
/// `Self::Usize`, they can be differently specified as necessary.
///
/// ## gdb
/// As a "bonus" this trait also provides required metadata needed
/// for gdb `XML` definition files (see [references](#references))
///
/// Example xml snippet required by `gdb`:
/// ```xml
/// <?xml version="1.0"?>
/// <!DOCTYPE target SYSTEM "gdb-target.dtd">
/// <target version="1.0">
///     <architecture>arm</architecture>
///     <feature name="org.gnu.gdb.arm.core">
///         <reg name="r0" bitsize="32" type="uint32"/>
///         <reg name="r1" bitsize="32" type="uint32"/>
///         <!-- ... -->
///         <reg name="r12" bitsize="32" type="uint32"/>
///         <reg name="sp" bitsize="32" type="data_ptr"/>
///         <reg name="lr" bitsize="32" type="uint32"/>
///         <reg name="pc" bitsize="32" type="code_ptr"/>
///         <reg name="cpsr" bitsize="32" type="int32"/>
///     </feature>
/// </target>
/// ```
///
/// NOTE: when [`https://github.com/rust-lang/rust/issues/29661`] is
/// resolved, all the associated types can actually default to
/// `Self::Usize` without any user interaction.
///
/// ### References
/// - [arm-core.xml file](https://github.com/bminor/binutils-gdb/blob/master/gdb/features/arm/arm-core.xml)
/// - [GDB Target Descriptions](https://sourceware.org/gdb/current/onlinedocs/gdb#Target-Descriptions)
/// - [Standard Target Features](https://sourceware.org/gdb/current/onlinedocs/gdb#Standard-Target-Features)
/// - [Arm Features](https://sourceware.org/gdb/current/onlinedocs/gdb#ARM-Features).
///
#[enum_dispatch]
pub trait ArchitectureDef: Send + Sync + 'static {
    /// The size in bits for `usize` on this architecture
    fn usize(&self) -> usize;

    /// The size in bits for `pc` on this architecture
    fn pc_size(&self) -> usize;

    /// The size in bits for `general purpose registers` on this architecture
    fn core_register_size(&self) -> usize;

    /// The size in bits for `data words` on this architecture
    fn data_word_size(&self) -> usize;

    /// The size in bits for `instruction words` on this architecture
    fn insn_word_size(&self) -> usize;

    /// The size in bits for `addresses` on this architecture
    fn addr_size(&self) -> usize;

    /// Returns an enum variant of the Architecture family
    /// for this specific Architecture variant
    fn architecture(&self) -> Arch;

    /// Returns the name of the Architecture Variant
    fn architecture_variant(&self) -> String {
        // typename gets the entire path, we just want the last part
        std::any::type_name::<Self>()
            .split("::")
            .last()
            .unwrap()
            .into()
    }

    /// Returns a struct of the registers
    fn registers(&self) -> Box<dyn CpuRegisterBank>;

    fn gdb_target_description(&self) -> GdbTargetDescriptionImpl;

    /// Generate target xml for *gdb* based on processor metadata from
    /// [`ArchitectureDef`]
    ///
    /// This provides a pretty good default impl, and mashes the [`ArchitectureVariant`]
    /// specific features into the XML via [`ArchitectureDef::target_xml`].
    ///
    /// With [gdbstub], there are two hooks for providing this XML. The first
    /// is with [target_description_xml](gdbstub::arch::Arch::target_description_xml),
    /// but this is more of a static/fixed description so is not as well suited as
    /// the second hook: [TargetDescriptionXmlOverride::target_description_xml](gdbstub::target::ext::target_description_xml_override::TargetDescriptionXmlOverride).
    /// This trait is implemented in `styx_machines`
    /// and simply calls this method. It's called at connection negotiation time,
    /// allowing our processor emulation to be fully initialized and ready to run.
    ///
    /// ## Parameters
    /// The `annex` parameter is for XML include references. For example, if the
    /// target_xml does an include such as: `<xi:include href="extra.xml"/>`,
    /// then GDB will ask for the XML doc  *b'extra.xml'*
    ///
    /// ## Register Types
    /// Register types are defined in the gdb user manual, section
    /// `G.3 Predefined Target Types`. In short, they look like `rust` types
    /// `(int8, uint8, ...)` but also include`code_ptr` and `data_ptr`.
    ///
    /// ## Feature and Architecture
    /// For the XML, we also need a *feature* and an *architecture*. For now,
    /// default implementations are provided by [`GdbTargetDescription`].
    ///
    /// ## References
    /// - [GDB Target Descriptions](https://sourceware.org/gdb/current/onlinedocs/gdb#Target-Descriptions)
    /// - [gdb repo's arm-core.xml](https://github.com/bminor/binutils-gdb/blob/master/gdb/features/arm/arm-core.xml)
    fn target_xml(&self, annex: &[u8]) -> Option<String> {
        const Q: &str = r#"""#; // double quote
        let arch_str = self.gdb_target_description().gdb_arch_name();

        let xml_version = format!("<?xml version={Q}1.0{Q}?>");
        let doc_type = r#"<!DOCTYPE target SYSTEM "gdb-target.dtd">"#;
        let target_tag = format!("<target version={Q}1.0{Q}>");
        let arch_tag = format!("    <architecture>{}</architecture>", arch_str);

        let mut xml = String::from("\n");
        xml.push_str(&format!("{}\n", xml_version));
        xml.push_str(&format!("{}\n", doc_type));
        xml.push_str(&format!("{}\n", target_tag));
        xml.push_str(&format!("{}\n", arch_tag));

        // get the list of features for this specific variant
        xml.push_str(&self.gdb_target_description().feature_xml());
        xml.push_str("</target>\n");

        match annex {
            // `annex`s are for XML include files, for example:
            // b"extra.xml" => Ok(EXTRA_XML.trim().as_bytes()),
            b"target.xml" => Some(xml),
            name => {
                warn!("Unexpected target XML request from gdbstub: {:?}", name);
                None
            }
        }
    }
}

#[enum_dispatch(GdbTargetDescription)]
pub enum GdbTargetDescriptionImpl {
    ArmCoreDescription(arm::gdb_targets::ArmCoreDescription),
    Aarch64CoreDescription(aarch64::gdb_targets::Aarch64CoreDescription),
    ArmMProfileDescription(arm::gdb_targets::ArmMProfileDescription),
    Armv7emDescription(arm::gdb_targets::Armv7emDescription),
    BlackfinDescription(blackfin::gdb_targets::BlackfinDescription),
    Mips32CpuDescription(mips32::gdb_targets::Mips32CpuTargetDescription),
    Mips64CaviumDescription(mips64::gdb_targets::Mips64CaviumTargetDescription),
    Mips64CpuDescription(mips64::gdb_targets::Mips64CpuTargetDescription),
    Msp430Description(msp430::gdb_targets::Msp430CpuTargetDescription),
    Msp430XDescription(msp430::gdb_targets::Msp430XCpuTargetDescription),
    PowerPC4xxDescription(ppc32::gdb_targets::Ppc4xxTargetDescription),
    PowerQUICCDescription(ppc32::gdb_targets::Mpc8xxTargetDescription),
    Sh1Description(superh::gdb_targets::ShDescription),
    Sh1DspDescription(superh::gdb_targets::ShDspDescription),
    Sh2ADescription(superh::gdb_targets::Sh2ADescription),
    Sh2ANoFpuDescription(superh::gdb_targets::Sh2ANoFpuDescription),
    Sh2Description(superh::gdb_targets::Sh2Description),
    Sh2EDescription(superh::gdb_targets::Sh2EDescription),
    Sh3Description(superh::gdb_targets::Sh3Description),
    Sh3Dspdescription(superh::gdb_targets::Sh3DspDescription),
    Sh3EDescription(superh::gdb_targets::Sh3EDescription),
    Sh4ADescription(superh::gdb_targets::Sh4ADescription),
    Sh4ALDspDescription(superh::gdb_targets::Sh4ALDspDescription),
    Sh4ANoFpuDescription(superh::gdb_targets::Sh4ANoFpuDescription),
    Sh4Description(superh::gdb_targets::Sh4Description),
    Sh4NoFpuDescription(superh::gdb_targets::Sh4NoFpuDescription),
}

/// A utility trait used to expidite the gdb implementation details,
/// since gdb details required for proper debugging vary wildly from
/// target to target.
///
/// Depending on the user use-case, this trait can quickly join the
/// hot-path, so this trait is enumerated via `enum-dispatch` to
/// assist in the auto-monomorphization of the underlying calls.
///
/// See [`GdbTargetDescriptionImpl`] for a link to all implementors of this trait.
#[enum_dispatch]
pub trait GdbTargetDescription {
    /// Provides the name of the [`ArchitectureVariant`]'s backing architecture
    /// as known by gdb, see [this](https://sourceware.org/gdb/current/onlinedocs/gdb#Targets)
    /// for applicable architecture names to be used in the target XML.
    /// An XML `architecture` element has this form:
    /// ```xml
    /// <architecture>arch</architecture>
    /// ```
    /// where _arch_ is one of the
    /// architectures from the set accepted by the gdb `set architecture`
    /// command.
    ///
    /// ## Examples:
    /// - `"arm"`
    /// - `"armv7e-m"`
    ///   - a la <https://github.com/bminor/binutils-gdb/tree/master/gdb/features>
    ///
    /// ### Note
    ///
    /// This is forced onto the variant implementation, due to increasing amounts
    /// of churn as more and more targets were being implemented
    fn gdb_arch_name(&self) -> String;

    /// Returns `\n` deliminated text of each feature
    /// provided by [`GdbTargetDescription::feature_xml_impl`]
    fn feature_xml(&self) -> String {
        self.feature_xml_impl().join("\n")
    }

    /// Returns a vec of the text of each gdb feature in the list
    ///
    /// This method should return the gdb features in [`String`] format,
    /// all gdb features applicable to the backing [`ArchitectureVariant`]
    /// and should be combined into a proper XML consumable by gdb-target.dtd.
    ///
    /// The easiest way to obtain the necessary content is via [`styx_util::gdb_xml`]
    fn feature_xml_impl(&self) -> Vec<String>;
}

/// Uses the [`gdb_target_description!`](macro@styx_macros::gdb_target_description)
/// macro to derive boilerplate gdbstub impls.
pub trait GdbRegistersHelper: gdbstub::arch::Registers {
    fn register_tank(&self) -> Vec<(self::backends::ArchRegister, Self::ProgramCounter)>;

    fn set_register_tank(&mut self, pairs: &[(CpuRegister, Self::ProgramCounter)]);

    /// Converts the idx into the gdb array into the appropriate
    /// [`ArchRegister`](crate::arch::backends::ArchRegister)
    fn from_usize(reg: usize) -> Option<backends::ArchRegister>;
}

/// Trait to describe a bank of registers for an architecture
pub trait CpuRegisterBank {
    /// Get the complete listing of [`CpuRegister`] for this specific
    /// [`ArchitectureVariant`]/[`ArchitectureDef`].
    fn registers(&self) -> Vec<CpuRegister>;
    /// Get the metadata about what the `pc` register is on this
    /// specific variant
    fn pc(&self) -> CpuRegister;
    /// Get the metadata about what the `sp` register is on this
    /// specific variant
    fn sp(&self) -> CpuRegister;
}

pub trait GdbArchIdSupportTrait:
    Into<crate::arch::backends::ArchRegister>
    + Copy
    + Clone
    + PartialEq
    + Eq
    + PartialOrd
    + Ord
    + std::hash::Hash
{
}
