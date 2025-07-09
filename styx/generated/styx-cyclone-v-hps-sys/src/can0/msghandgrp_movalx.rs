// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `msghandgrp_MOVALX` reader"]
pub type R = crate::R<MsghandgrpMovalxSpec>;
#[doc = "Register `msghandgrp_MOVALX` writer"]
pub type W = crate::W<MsghandgrpMovalxSpec>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOVALA register. Array index i corresponds to byte i of the MOVALA register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgValA0 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgValA0> for bool {
    #[inline(always)]
    fn from(variant: MsgValA0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgValA_0` reader - Each bit in this field is a logical OR of a byte of the MOVALA register. Array index i corresponds to byte i of the MOVALA register."]
pub type MsgValA0R = crate::BitReader<MsgValA0>;
impl MsgValA0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgValA0 {
        match self.bits {
            false => MsgValA0::Ignored,
            true => MsgValA0::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgValA0::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgValA0::Considered
    }
}
#[doc = "Field `MsgValA_0` writer - Each bit in this field is a logical OR of a byte of the MOVALA register. Array index i corresponds to byte i of the MOVALA register."]
pub type MsgValA0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOVALA register. Array index i corresponds to byte i of the MOVALA register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgValA1 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgValA1> for bool {
    #[inline(always)]
    fn from(variant: MsgValA1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgValA_1` reader - Each bit in this field is a logical OR of a byte of the MOVALA register. Array index i corresponds to byte i of the MOVALA register."]
pub type MsgValA1R = crate::BitReader<MsgValA1>;
impl MsgValA1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgValA1 {
        match self.bits {
            false => MsgValA1::Ignored,
            true => MsgValA1::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgValA1::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgValA1::Considered
    }
}
#[doc = "Field `MsgValA_1` writer - Each bit in this field is a logical OR of a byte of the MOVALA register. Array index i corresponds to byte i of the MOVALA register."]
pub type MsgValA1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOVALA register. Array index i corresponds to byte i of the MOVALA register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgValA2 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgValA2> for bool {
    #[inline(always)]
    fn from(variant: MsgValA2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgValA_2` reader - Each bit in this field is a logical OR of a byte of the MOVALA register. Array index i corresponds to byte i of the MOVALA register."]
pub type MsgValA2R = crate::BitReader<MsgValA2>;
impl MsgValA2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgValA2 {
        match self.bits {
            false => MsgValA2::Ignored,
            true => MsgValA2::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgValA2::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgValA2::Considered
    }
}
#[doc = "Field `MsgValA_2` writer - Each bit in this field is a logical OR of a byte of the MOVALA register. Array index i corresponds to byte i of the MOVALA register."]
pub type MsgValA2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOVALA register. Array index i corresponds to byte i of the MOVALA register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgValA3 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgValA3> for bool {
    #[inline(always)]
    fn from(variant: MsgValA3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgValA_3` reader - Each bit in this field is a logical OR of a byte of the MOVALA register. Array index i corresponds to byte i of the MOVALA register."]
pub type MsgValA3R = crate::BitReader<MsgValA3>;
impl MsgValA3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgValA3 {
        match self.bits {
            false => MsgValA3::Ignored,
            true => MsgValA3::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgValA3::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgValA3::Considered
    }
}
#[doc = "Field `MsgValA_3` writer - Each bit in this field is a logical OR of a byte of the MOVALA register. Array index i corresponds to byte i of the MOVALA register."]
pub type MsgValA3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOVALB register. Array index i corresponds to byte i of the MOVALB register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgValB0 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgValB0> for bool {
    #[inline(always)]
    fn from(variant: MsgValB0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgValB_0` reader - Each bit in this field is a logical OR of a byte of the MOVALB register. Array index i corresponds to byte i of the MOVALB register."]
pub type MsgValB0R = crate::BitReader<MsgValB0>;
impl MsgValB0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgValB0 {
        match self.bits {
            false => MsgValB0::Ignored,
            true => MsgValB0::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgValB0::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgValB0::Considered
    }
}
#[doc = "Field `MsgValB_0` writer - Each bit in this field is a logical OR of a byte of the MOVALB register. Array index i corresponds to byte i of the MOVALB register."]
pub type MsgValB0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOVALB register. Array index i corresponds to byte i of the MOVALB register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgValB1 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgValB1> for bool {
    #[inline(always)]
    fn from(variant: MsgValB1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgValB_1` reader - Each bit in this field is a logical OR of a byte of the MOVALB register. Array index i corresponds to byte i of the MOVALB register."]
pub type MsgValB1R = crate::BitReader<MsgValB1>;
impl MsgValB1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgValB1 {
        match self.bits {
            false => MsgValB1::Ignored,
            true => MsgValB1::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgValB1::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgValB1::Considered
    }
}
#[doc = "Field `MsgValB_1` writer - Each bit in this field is a logical OR of a byte of the MOVALB register. Array index i corresponds to byte i of the MOVALB register."]
pub type MsgValB1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOVALB register. Array index i corresponds to byte i of the MOVALB register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgValB2 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgValB2> for bool {
    #[inline(always)]
    fn from(variant: MsgValB2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgValB_2` reader - Each bit in this field is a logical OR of a byte of the MOVALB register. Array index i corresponds to byte i of the MOVALB register."]
pub type MsgValB2R = crate::BitReader<MsgValB2>;
impl MsgValB2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgValB2 {
        match self.bits {
            false => MsgValB2::Ignored,
            true => MsgValB2::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgValB2::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgValB2::Considered
    }
}
#[doc = "Field `MsgValB_2` writer - Each bit in this field is a logical OR of a byte of the MOVALB register. Array index i corresponds to byte i of the MOVALB register."]
pub type MsgValB2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOVALB register. Array index i corresponds to byte i of the MOVALB register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgValB3 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgValB3> for bool {
    #[inline(always)]
    fn from(variant: MsgValB3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgValB_3` reader - Each bit in this field is a logical OR of a byte of the MOVALB register. Array index i corresponds to byte i of the MOVALB register."]
pub type MsgValB3R = crate::BitReader<MsgValB3>;
impl MsgValB3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgValB3 {
        match self.bits {
            false => MsgValB3::Ignored,
            true => MsgValB3::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgValB3::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgValB3::Considered
    }
}
#[doc = "Field `MsgValB_3` writer - Each bit in this field is a logical OR of a byte of the MOVALB register. Array index i corresponds to byte i of the MOVALB register."]
pub type MsgValB3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOVALC register. Array index i corresponds to byte i of the MOVALC register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgValC0 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgValC0> for bool {
    #[inline(always)]
    fn from(variant: MsgValC0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgValC_0` reader - Each bit in this field is a logical OR of a byte of the MOVALC register. Array index i corresponds to byte i of the MOVALC register."]
pub type MsgValC0R = crate::BitReader<MsgValC0>;
impl MsgValC0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgValC0 {
        match self.bits {
            false => MsgValC0::Ignored,
            true => MsgValC0::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgValC0::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgValC0::Considered
    }
}
#[doc = "Field `MsgValC_0` writer - Each bit in this field is a logical OR of a byte of the MOVALC register. Array index i corresponds to byte i of the MOVALC register."]
pub type MsgValC0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOVALC register. Array index i corresponds to byte i of the MOVALC register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgValC1 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgValC1> for bool {
    #[inline(always)]
    fn from(variant: MsgValC1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgValC_1` reader - Each bit in this field is a logical OR of a byte of the MOVALC register. Array index i corresponds to byte i of the MOVALC register."]
pub type MsgValC1R = crate::BitReader<MsgValC1>;
impl MsgValC1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgValC1 {
        match self.bits {
            false => MsgValC1::Ignored,
            true => MsgValC1::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgValC1::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgValC1::Considered
    }
}
#[doc = "Field `MsgValC_1` writer - Each bit in this field is a logical OR of a byte of the MOVALC register. Array index i corresponds to byte i of the MOVALC register."]
pub type MsgValC1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOVALC register. Array index i corresponds to byte i of the MOVALC register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgValC2 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgValC2> for bool {
    #[inline(always)]
    fn from(variant: MsgValC2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgValC_2` reader - Each bit in this field is a logical OR of a byte of the MOVALC register. Array index i corresponds to byte i of the MOVALC register."]
pub type MsgValC2R = crate::BitReader<MsgValC2>;
impl MsgValC2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgValC2 {
        match self.bits {
            false => MsgValC2::Ignored,
            true => MsgValC2::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgValC2::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgValC2::Considered
    }
}
#[doc = "Field `MsgValC_2` writer - Each bit in this field is a logical OR of a byte of the MOVALC register. Array index i corresponds to byte i of the MOVALC register."]
pub type MsgValC2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOVALC register. Array index i corresponds to byte i of the MOVALC register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgValC3 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgValC3> for bool {
    #[inline(always)]
    fn from(variant: MsgValC3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgValC_3` reader - Each bit in this field is a logical OR of a byte of the MOVALC register. Array index i corresponds to byte i of the MOVALC register."]
pub type MsgValC3R = crate::BitReader<MsgValC3>;
impl MsgValC3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgValC3 {
        match self.bits {
            false => MsgValC3::Ignored,
            true => MsgValC3::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgValC3::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgValC3::Considered
    }
}
#[doc = "Field `MsgValC_3` writer - Each bit in this field is a logical OR of a byte of the MOVALC register. Array index i corresponds to byte i of the MOVALC register."]
pub type MsgValC3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOVALD register. Array index i corresponds to byte i of the MOVALD register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgValD0 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgValD0> for bool {
    #[inline(always)]
    fn from(variant: MsgValD0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgValD_0` reader - Each bit in this field is a logical OR of a byte of the MOVALD register. Array index i corresponds to byte i of the MOVALD register."]
pub type MsgValD0R = crate::BitReader<MsgValD0>;
impl MsgValD0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgValD0 {
        match self.bits {
            false => MsgValD0::Ignored,
            true => MsgValD0::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgValD0::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgValD0::Considered
    }
}
#[doc = "Field `MsgValD_0` writer - Each bit in this field is a logical OR of a byte of the MOVALD register. Array index i corresponds to byte i of the MOVALD register."]
pub type MsgValD0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOVALD register. Array index i corresponds to byte i of the MOVALD register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgValD1 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgValD1> for bool {
    #[inline(always)]
    fn from(variant: MsgValD1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgValD_1` reader - Each bit in this field is a logical OR of a byte of the MOVALD register. Array index i corresponds to byte i of the MOVALD register."]
pub type MsgValD1R = crate::BitReader<MsgValD1>;
impl MsgValD1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgValD1 {
        match self.bits {
            false => MsgValD1::Ignored,
            true => MsgValD1::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgValD1::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgValD1::Considered
    }
}
#[doc = "Field `MsgValD_1` writer - Each bit in this field is a logical OR of a byte of the MOVALD register. Array index i corresponds to byte i of the MOVALD register."]
pub type MsgValD1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOVALD register. Array index i corresponds to byte i of the MOVALD register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgValD2 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgValD2> for bool {
    #[inline(always)]
    fn from(variant: MsgValD2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgValD_2` reader - Each bit in this field is a logical OR of a byte of the MOVALD register. Array index i corresponds to byte i of the MOVALD register."]
pub type MsgValD2R = crate::BitReader<MsgValD2>;
impl MsgValD2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgValD2 {
        match self.bits {
            false => MsgValD2::Ignored,
            true => MsgValD2::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgValD2::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgValD2::Considered
    }
}
#[doc = "Field `MsgValD_2` writer - Each bit in this field is a logical OR of a byte of the MOVALD register. Array index i corresponds to byte i of the MOVALD register."]
pub type MsgValD2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOVALD register. Array index i corresponds to byte i of the MOVALD register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgValD3 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgValD3> for bool {
    #[inline(always)]
    fn from(variant: MsgValD3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgValD_3` reader - Each bit in this field is a logical OR of a byte of the MOVALD register. Array index i corresponds to byte i of the MOVALD register."]
pub type MsgValD3R = crate::BitReader<MsgValD3>;
impl MsgValD3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgValD3 {
        match self.bits {
            false => MsgValD3::Ignored,
            true => MsgValD3::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgValD3::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgValD3::Considered
    }
}
#[doc = "Field `MsgValD_3` writer - Each bit in this field is a logical OR of a byte of the MOVALD register. Array index i corresponds to byte i of the MOVALD register."]
pub type MsgValD3W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Each bit in this field is a logical OR of a byte of the MOVALA register. Array index i corresponds to byte i of the MOVALA register."]
    #[inline(always)]
    pub fn msg_val_a_0(&self) -> MsgValA0R {
        MsgValA0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Each bit in this field is a logical OR of a byte of the MOVALA register. Array index i corresponds to byte i of the MOVALA register."]
    #[inline(always)]
    pub fn msg_val_a_1(&self) -> MsgValA1R {
        MsgValA1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Each bit in this field is a logical OR of a byte of the MOVALA register. Array index i corresponds to byte i of the MOVALA register."]
    #[inline(always)]
    pub fn msg_val_a_2(&self) -> MsgValA2R {
        MsgValA2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Each bit in this field is a logical OR of a byte of the MOVALA register. Array index i corresponds to byte i of the MOVALA register."]
    #[inline(always)]
    pub fn msg_val_a_3(&self) -> MsgValA3R {
        MsgValA3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Each bit in this field is a logical OR of a byte of the MOVALB register. Array index i corresponds to byte i of the MOVALB register."]
    #[inline(always)]
    pub fn msg_val_b_0(&self) -> MsgValB0R {
        MsgValB0R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Each bit in this field is a logical OR of a byte of the MOVALB register. Array index i corresponds to byte i of the MOVALB register."]
    #[inline(always)]
    pub fn msg_val_b_1(&self) -> MsgValB1R {
        MsgValB1R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Each bit in this field is a logical OR of a byte of the MOVALB register. Array index i corresponds to byte i of the MOVALB register."]
    #[inline(always)]
    pub fn msg_val_b_2(&self) -> MsgValB2R {
        MsgValB2R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Each bit in this field is a logical OR of a byte of the MOVALB register. Array index i corresponds to byte i of the MOVALB register."]
    #[inline(always)]
    pub fn msg_val_b_3(&self) -> MsgValB3R {
        MsgValB3R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Each bit in this field is a logical OR of a byte of the MOVALC register. Array index i corresponds to byte i of the MOVALC register."]
    #[inline(always)]
    pub fn msg_val_c_0(&self) -> MsgValC0R {
        MsgValC0R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Each bit in this field is a logical OR of a byte of the MOVALC register. Array index i corresponds to byte i of the MOVALC register."]
    #[inline(always)]
    pub fn msg_val_c_1(&self) -> MsgValC1R {
        MsgValC1R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Each bit in this field is a logical OR of a byte of the MOVALC register. Array index i corresponds to byte i of the MOVALC register."]
    #[inline(always)]
    pub fn msg_val_c_2(&self) -> MsgValC2R {
        MsgValC2R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Each bit in this field is a logical OR of a byte of the MOVALC register. Array index i corresponds to byte i of the MOVALC register."]
    #[inline(always)]
    pub fn msg_val_c_3(&self) -> MsgValC3R {
        MsgValC3R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Each bit in this field is a logical OR of a byte of the MOVALD register. Array index i corresponds to byte i of the MOVALD register."]
    #[inline(always)]
    pub fn msg_val_d_0(&self) -> MsgValD0R {
        MsgValD0R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Each bit in this field is a logical OR of a byte of the MOVALD register. Array index i corresponds to byte i of the MOVALD register."]
    #[inline(always)]
    pub fn msg_val_d_1(&self) -> MsgValD1R {
        MsgValD1R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Each bit in this field is a logical OR of a byte of the MOVALD register. Array index i corresponds to byte i of the MOVALD register."]
    #[inline(always)]
    pub fn msg_val_d_2(&self) -> MsgValD2R {
        MsgValD2R::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Each bit in this field is a logical OR of a byte of the MOVALD register. Array index i corresponds to byte i of the MOVALD register."]
    #[inline(always)]
    pub fn msg_val_d_3(&self) -> MsgValD3R {
        MsgValD3R::new(((self.bits >> 15) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Each bit in this field is a logical OR of a byte of the MOVALA register. Array index i corresponds to byte i of the MOVALA register."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_a_0(&mut self) -> MsgValA0W<MsghandgrpMovalxSpec> {
        MsgValA0W::new(self, 0)
    }
    #[doc = "Bit 1 - Each bit in this field is a logical OR of a byte of the MOVALA register. Array index i corresponds to byte i of the MOVALA register."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_a_1(&mut self) -> MsgValA1W<MsghandgrpMovalxSpec> {
        MsgValA1W::new(self, 1)
    }
    #[doc = "Bit 2 - Each bit in this field is a logical OR of a byte of the MOVALA register. Array index i corresponds to byte i of the MOVALA register."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_a_2(&mut self) -> MsgValA2W<MsghandgrpMovalxSpec> {
        MsgValA2W::new(self, 2)
    }
    #[doc = "Bit 3 - Each bit in this field is a logical OR of a byte of the MOVALA register. Array index i corresponds to byte i of the MOVALA register."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_a_3(&mut self) -> MsgValA3W<MsghandgrpMovalxSpec> {
        MsgValA3W::new(self, 3)
    }
    #[doc = "Bit 4 - Each bit in this field is a logical OR of a byte of the MOVALB register. Array index i corresponds to byte i of the MOVALB register."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_b_0(&mut self) -> MsgValB0W<MsghandgrpMovalxSpec> {
        MsgValB0W::new(self, 4)
    }
    #[doc = "Bit 5 - Each bit in this field is a logical OR of a byte of the MOVALB register. Array index i corresponds to byte i of the MOVALB register."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_b_1(&mut self) -> MsgValB1W<MsghandgrpMovalxSpec> {
        MsgValB1W::new(self, 5)
    }
    #[doc = "Bit 6 - Each bit in this field is a logical OR of a byte of the MOVALB register. Array index i corresponds to byte i of the MOVALB register."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_b_2(&mut self) -> MsgValB2W<MsghandgrpMovalxSpec> {
        MsgValB2W::new(self, 6)
    }
    #[doc = "Bit 7 - Each bit in this field is a logical OR of a byte of the MOVALB register. Array index i corresponds to byte i of the MOVALB register."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_b_3(&mut self) -> MsgValB3W<MsghandgrpMovalxSpec> {
        MsgValB3W::new(self, 7)
    }
    #[doc = "Bit 8 - Each bit in this field is a logical OR of a byte of the MOVALC register. Array index i corresponds to byte i of the MOVALC register."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_c_0(&mut self) -> MsgValC0W<MsghandgrpMovalxSpec> {
        MsgValC0W::new(self, 8)
    }
    #[doc = "Bit 9 - Each bit in this field is a logical OR of a byte of the MOVALC register. Array index i corresponds to byte i of the MOVALC register."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_c_1(&mut self) -> MsgValC1W<MsghandgrpMovalxSpec> {
        MsgValC1W::new(self, 9)
    }
    #[doc = "Bit 10 - Each bit in this field is a logical OR of a byte of the MOVALC register. Array index i corresponds to byte i of the MOVALC register."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_c_2(&mut self) -> MsgValC2W<MsghandgrpMovalxSpec> {
        MsgValC2W::new(self, 10)
    }
    #[doc = "Bit 11 - Each bit in this field is a logical OR of a byte of the MOVALC register. Array index i corresponds to byte i of the MOVALC register."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_c_3(&mut self) -> MsgValC3W<MsghandgrpMovalxSpec> {
        MsgValC3W::new(self, 11)
    }
    #[doc = "Bit 12 - Each bit in this field is a logical OR of a byte of the MOVALD register. Array index i corresponds to byte i of the MOVALD register."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_d_0(&mut self) -> MsgValD0W<MsghandgrpMovalxSpec> {
        MsgValD0W::new(self, 12)
    }
    #[doc = "Bit 13 - Each bit in this field is a logical OR of a byte of the MOVALD register. Array index i corresponds to byte i of the MOVALD register."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_d_1(&mut self) -> MsgValD1W<MsghandgrpMovalxSpec> {
        MsgValD1W::new(self, 13)
    }
    #[doc = "Bit 14 - Each bit in this field is a logical OR of a byte of the MOVALD register. Array index i corresponds to byte i of the MOVALD register."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_d_2(&mut self) -> MsgValD2W<MsghandgrpMovalxSpec> {
        MsgValD2W::new(self, 14)
    }
    #[doc = "Bit 15 - Each bit in this field is a logical OR of a byte of the MOVALD register. Array index i corresponds to byte i of the MOVALD register."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_d_3(&mut self) -> MsgValD3W<MsghandgrpMovalxSpec> {
        MsgValD3W::new(self, 15)
    }
}
#[doc = "Reading this register allows the CPU to quickly detect if any of the message valid bits in each of the MOVALA, MOVALB, MOVALC, and MOVALD Message Valid Registers are set.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_movalx::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MsghandgrpMovalxSpec;
impl crate::RegisterSpec for MsghandgrpMovalxSpec {
    type Ux = u32;
    const OFFSET: u64 = 192u64;
}
#[doc = "`read()` method returns [`msghandgrp_movalx::R`](R) reader structure"]
impl crate::Readable for MsghandgrpMovalxSpec {}
#[doc = "`reset()` method sets msghandgrp_MOVALX to value 0"]
impl crate::Resettable for MsghandgrpMovalxSpec {
    const RESET_VALUE: u32 = 0;
}
