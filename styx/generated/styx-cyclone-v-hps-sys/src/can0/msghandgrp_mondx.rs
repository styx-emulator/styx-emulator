// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `msghandgrp_MONDX` reader"]
pub type R = crate::R<MsghandgrpMondxSpec>;
#[doc = "Register `msghandgrp_MONDX` writer"]
pub type W = crate::W<MsghandgrpMondxSpec>;
#[doc = "Each bit in this field is a logical OR of a byte of the MONDA register. Array index i corresponds to byte i of the MONDA register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDatA0 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDatA0> for bool {
    #[inline(always)]
    fn from(variant: NewDatA0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDatA_0` reader - Each bit in this field is a logical OR of a byte of the MONDA register. Array index i corresponds to byte i of the MONDA register."]
pub type NewDatA0R = crate::BitReader<NewDatA0>;
impl NewDatA0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDatA0 {
        match self.bits {
            false => NewDatA0::NotWritten,
            true => NewDatA0::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDatA0::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDatA0::Written
    }
}
#[doc = "Field `NewDatA_0` writer - Each bit in this field is a logical OR of a byte of the MONDA register. Array index i corresponds to byte i of the MONDA register."]
pub type NewDatA0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MONDA register. Array index i corresponds to byte i of the MONDA register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDatA1 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDatA1> for bool {
    #[inline(always)]
    fn from(variant: NewDatA1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDatA_1` reader - Each bit in this field is a logical OR of a byte of the MONDA register. Array index i corresponds to byte i of the MONDA register."]
pub type NewDatA1R = crate::BitReader<NewDatA1>;
impl NewDatA1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDatA1 {
        match self.bits {
            false => NewDatA1::NotWritten,
            true => NewDatA1::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDatA1::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDatA1::Written
    }
}
#[doc = "Field `NewDatA_1` writer - Each bit in this field is a logical OR of a byte of the MONDA register. Array index i corresponds to byte i of the MONDA register."]
pub type NewDatA1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MONDA register. Array index i corresponds to byte i of the MONDA register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDatA2 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDatA2> for bool {
    #[inline(always)]
    fn from(variant: NewDatA2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDatA_2` reader - Each bit in this field is a logical OR of a byte of the MONDA register. Array index i corresponds to byte i of the MONDA register."]
pub type NewDatA2R = crate::BitReader<NewDatA2>;
impl NewDatA2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDatA2 {
        match self.bits {
            false => NewDatA2::NotWritten,
            true => NewDatA2::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDatA2::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDatA2::Written
    }
}
#[doc = "Field `NewDatA_2` writer - Each bit in this field is a logical OR of a byte of the MONDA register. Array index i corresponds to byte i of the MONDA register."]
pub type NewDatA2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MONDA register. Array index i corresponds to byte i of the MONDA register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDatA3 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDatA3> for bool {
    #[inline(always)]
    fn from(variant: NewDatA3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDatA_3` reader - Each bit in this field is a logical OR of a byte of the MONDA register. Array index i corresponds to byte i of the MONDA register."]
pub type NewDatA3R = crate::BitReader<NewDatA3>;
impl NewDatA3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDatA3 {
        match self.bits {
            false => NewDatA3::NotWritten,
            true => NewDatA3::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDatA3::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDatA3::Written
    }
}
#[doc = "Field `NewDatA_3` writer - Each bit in this field is a logical OR of a byte of the MONDA register. Array index i corresponds to byte i of the MONDA register."]
pub type NewDatA3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MONDB register. Array index i corresponds to byte i of the MONDB register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDatB0 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDatB0> for bool {
    #[inline(always)]
    fn from(variant: NewDatB0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDatB_0` reader - Each bit in this field is a logical OR of a byte of the MONDB register. Array index i corresponds to byte i of the MONDB register."]
pub type NewDatB0R = crate::BitReader<NewDatB0>;
impl NewDatB0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDatB0 {
        match self.bits {
            false => NewDatB0::NotWritten,
            true => NewDatB0::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDatB0::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDatB0::Written
    }
}
#[doc = "Field `NewDatB_0` writer - Each bit in this field is a logical OR of a byte of the MONDB register. Array index i corresponds to byte i of the MONDB register."]
pub type NewDatB0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MONDB register. Array index i corresponds to byte i of the MONDB register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDatB1 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDatB1> for bool {
    #[inline(always)]
    fn from(variant: NewDatB1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDatB_1` reader - Each bit in this field is a logical OR of a byte of the MONDB register. Array index i corresponds to byte i of the MONDB register."]
pub type NewDatB1R = crate::BitReader<NewDatB1>;
impl NewDatB1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDatB1 {
        match self.bits {
            false => NewDatB1::NotWritten,
            true => NewDatB1::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDatB1::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDatB1::Written
    }
}
#[doc = "Field `NewDatB_1` writer - Each bit in this field is a logical OR of a byte of the MONDB register. Array index i corresponds to byte i of the MONDB register."]
pub type NewDatB1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MONDB register. Array index i corresponds to byte i of the MONDB register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDatB2 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDatB2> for bool {
    #[inline(always)]
    fn from(variant: NewDatB2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDatB_2` reader - Each bit in this field is a logical OR of a byte of the MONDB register. Array index i corresponds to byte i of the MONDB register."]
pub type NewDatB2R = crate::BitReader<NewDatB2>;
impl NewDatB2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDatB2 {
        match self.bits {
            false => NewDatB2::NotWritten,
            true => NewDatB2::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDatB2::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDatB2::Written
    }
}
#[doc = "Field `NewDatB_2` writer - Each bit in this field is a logical OR of a byte of the MONDB register. Array index i corresponds to byte i of the MONDB register."]
pub type NewDatB2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MONDB register. Array index i corresponds to byte i of the MONDB register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDatB3 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDatB3> for bool {
    #[inline(always)]
    fn from(variant: NewDatB3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDatB_3` reader - Each bit in this field is a logical OR of a byte of the MONDB register. Array index i corresponds to byte i of the MONDB register."]
pub type NewDatB3R = crate::BitReader<NewDatB3>;
impl NewDatB3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDatB3 {
        match self.bits {
            false => NewDatB3::NotWritten,
            true => NewDatB3::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDatB3::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDatB3::Written
    }
}
#[doc = "Field `NewDatB_3` writer - Each bit in this field is a logical OR of a byte of the MONDB register. Array index i corresponds to byte i of the MONDB register."]
pub type NewDatB3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MONDC register. Array index i corresponds to byte i of the MONDC register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDatC0 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDatC0> for bool {
    #[inline(always)]
    fn from(variant: NewDatC0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDatC_0` reader - Each bit in this field is a logical OR of a byte of the MONDC register. Array index i corresponds to byte i of the MONDC register."]
pub type NewDatC0R = crate::BitReader<NewDatC0>;
impl NewDatC0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDatC0 {
        match self.bits {
            false => NewDatC0::NotWritten,
            true => NewDatC0::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDatC0::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDatC0::Written
    }
}
#[doc = "Field `NewDatC_0` writer - Each bit in this field is a logical OR of a byte of the MONDC register. Array index i corresponds to byte i of the MONDC register."]
pub type NewDatC0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MONDC register. Array index i corresponds to byte i of the MONDC register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDatC1 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDatC1> for bool {
    #[inline(always)]
    fn from(variant: NewDatC1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDatC_1` reader - Each bit in this field is a logical OR of a byte of the MONDC register. Array index i corresponds to byte i of the MONDC register."]
pub type NewDatC1R = crate::BitReader<NewDatC1>;
impl NewDatC1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDatC1 {
        match self.bits {
            false => NewDatC1::NotWritten,
            true => NewDatC1::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDatC1::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDatC1::Written
    }
}
#[doc = "Field `NewDatC_1` writer - Each bit in this field is a logical OR of a byte of the MONDC register. Array index i corresponds to byte i of the MONDC register."]
pub type NewDatC1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MONDC register. Array index i corresponds to byte i of the MONDC register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDatC2 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDatC2> for bool {
    #[inline(always)]
    fn from(variant: NewDatC2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDatC_2` reader - Each bit in this field is a logical OR of a byte of the MONDC register. Array index i corresponds to byte i of the MONDC register."]
pub type NewDatC2R = crate::BitReader<NewDatC2>;
impl NewDatC2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDatC2 {
        match self.bits {
            false => NewDatC2::NotWritten,
            true => NewDatC2::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDatC2::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDatC2::Written
    }
}
#[doc = "Field `NewDatC_2` writer - Each bit in this field is a logical OR of a byte of the MONDC register. Array index i corresponds to byte i of the MONDC register."]
pub type NewDatC2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MONDC register. Array index i corresponds to byte i of the MONDC register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDatC3 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDatC3> for bool {
    #[inline(always)]
    fn from(variant: NewDatC3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDatC_3` reader - Each bit in this field is a logical OR of a byte of the MONDC register. Array index i corresponds to byte i of the MONDC register."]
pub type NewDatC3R = crate::BitReader<NewDatC3>;
impl NewDatC3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDatC3 {
        match self.bits {
            false => NewDatC3::NotWritten,
            true => NewDatC3::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDatC3::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDatC3::Written
    }
}
#[doc = "Field `NewDatC_3` writer - Each bit in this field is a logical OR of a byte of the MONDC register. Array index i corresponds to byte i of the MONDC register."]
pub type NewDatC3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MONDD register. Array index i corresponds to byte i of the MONDD register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDatD0 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDatD0> for bool {
    #[inline(always)]
    fn from(variant: NewDatD0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDatD_0` reader - Each bit in this field is a logical OR of a byte of the MONDD register. Array index i corresponds to byte i of the MONDD register."]
pub type NewDatD0R = crate::BitReader<NewDatD0>;
impl NewDatD0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDatD0 {
        match self.bits {
            false => NewDatD0::NotWritten,
            true => NewDatD0::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDatD0::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDatD0::Written
    }
}
#[doc = "Field `NewDatD_0` writer - Each bit in this field is a logical OR of a byte of the MONDD register. Array index i corresponds to byte i of the MONDD register."]
pub type NewDatD0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MONDD register. Array index i corresponds to byte i of the MONDD register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDatD1 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDatD1> for bool {
    #[inline(always)]
    fn from(variant: NewDatD1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDatD_1` reader - Each bit in this field is a logical OR of a byte of the MONDD register. Array index i corresponds to byte i of the MONDD register."]
pub type NewDatD1R = crate::BitReader<NewDatD1>;
impl NewDatD1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDatD1 {
        match self.bits {
            false => NewDatD1::NotWritten,
            true => NewDatD1::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDatD1::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDatD1::Written
    }
}
#[doc = "Field `NewDatD_1` writer - Each bit in this field is a logical OR of a byte of the MONDD register. Array index i corresponds to byte i of the MONDD register."]
pub type NewDatD1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MONDD register. Array index i corresponds to byte i of the MONDD register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDatD2 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDatD2> for bool {
    #[inline(always)]
    fn from(variant: NewDatD2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDatD_2` reader - Each bit in this field is a logical OR of a byte of the MONDD register. Array index i corresponds to byte i of the MONDD register."]
pub type NewDatD2R = crate::BitReader<NewDatD2>;
impl NewDatD2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDatD2 {
        match self.bits {
            false => NewDatD2::NotWritten,
            true => NewDatD2::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDatD2::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDatD2::Written
    }
}
#[doc = "Field `NewDatD_2` writer - Each bit in this field is a logical OR of a byte of the MONDD register. Array index i corresponds to byte i of the MONDD register."]
pub type NewDatD2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MONDD register. Array index i corresponds to byte i of the MONDD register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDatD3 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDatD3> for bool {
    #[inline(always)]
    fn from(variant: NewDatD3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDatD_3` reader - Each bit in this field is a logical OR of a byte of the MONDD register. Array index i corresponds to byte i of the MONDD register."]
pub type NewDatD3R = crate::BitReader<NewDatD3>;
impl NewDatD3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDatD3 {
        match self.bits {
            false => NewDatD3::NotWritten,
            true => NewDatD3::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDatD3::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDatD3::Written
    }
}
#[doc = "Field `NewDatD_3` writer - Each bit in this field is a logical OR of a byte of the MONDD register. Array index i corresponds to byte i of the MONDD register."]
pub type NewDatD3W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Each bit in this field is a logical OR of a byte of the MONDA register. Array index i corresponds to byte i of the MONDA register."]
    #[inline(always)]
    pub fn new_dat_a_0(&self) -> NewDatA0R {
        NewDatA0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Each bit in this field is a logical OR of a byte of the MONDA register. Array index i corresponds to byte i of the MONDA register."]
    #[inline(always)]
    pub fn new_dat_a_1(&self) -> NewDatA1R {
        NewDatA1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Each bit in this field is a logical OR of a byte of the MONDA register. Array index i corresponds to byte i of the MONDA register."]
    #[inline(always)]
    pub fn new_dat_a_2(&self) -> NewDatA2R {
        NewDatA2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Each bit in this field is a logical OR of a byte of the MONDA register. Array index i corresponds to byte i of the MONDA register."]
    #[inline(always)]
    pub fn new_dat_a_3(&self) -> NewDatA3R {
        NewDatA3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Each bit in this field is a logical OR of a byte of the MONDB register. Array index i corresponds to byte i of the MONDB register."]
    #[inline(always)]
    pub fn new_dat_b_0(&self) -> NewDatB0R {
        NewDatB0R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Each bit in this field is a logical OR of a byte of the MONDB register. Array index i corresponds to byte i of the MONDB register."]
    #[inline(always)]
    pub fn new_dat_b_1(&self) -> NewDatB1R {
        NewDatB1R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Each bit in this field is a logical OR of a byte of the MONDB register. Array index i corresponds to byte i of the MONDB register."]
    #[inline(always)]
    pub fn new_dat_b_2(&self) -> NewDatB2R {
        NewDatB2R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Each bit in this field is a logical OR of a byte of the MONDB register. Array index i corresponds to byte i of the MONDB register."]
    #[inline(always)]
    pub fn new_dat_b_3(&self) -> NewDatB3R {
        NewDatB3R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Each bit in this field is a logical OR of a byte of the MONDC register. Array index i corresponds to byte i of the MONDC register."]
    #[inline(always)]
    pub fn new_dat_c_0(&self) -> NewDatC0R {
        NewDatC0R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Each bit in this field is a logical OR of a byte of the MONDC register. Array index i corresponds to byte i of the MONDC register."]
    #[inline(always)]
    pub fn new_dat_c_1(&self) -> NewDatC1R {
        NewDatC1R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Each bit in this field is a logical OR of a byte of the MONDC register. Array index i corresponds to byte i of the MONDC register."]
    #[inline(always)]
    pub fn new_dat_c_2(&self) -> NewDatC2R {
        NewDatC2R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Each bit in this field is a logical OR of a byte of the MONDC register. Array index i corresponds to byte i of the MONDC register."]
    #[inline(always)]
    pub fn new_dat_c_3(&self) -> NewDatC3R {
        NewDatC3R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Each bit in this field is a logical OR of a byte of the MONDD register. Array index i corresponds to byte i of the MONDD register."]
    #[inline(always)]
    pub fn new_dat_d_0(&self) -> NewDatD0R {
        NewDatD0R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Each bit in this field is a logical OR of a byte of the MONDD register. Array index i corresponds to byte i of the MONDD register."]
    #[inline(always)]
    pub fn new_dat_d_1(&self) -> NewDatD1R {
        NewDatD1R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Each bit in this field is a logical OR of a byte of the MONDD register. Array index i corresponds to byte i of the MONDD register."]
    #[inline(always)]
    pub fn new_dat_d_2(&self) -> NewDatD2R {
        NewDatD2R::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Each bit in this field is a logical OR of a byte of the MONDD register. Array index i corresponds to byte i of the MONDD register."]
    #[inline(always)]
    pub fn new_dat_d_3(&self) -> NewDatD3R {
        NewDatD3R::new(((self.bits >> 15) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Each bit in this field is a logical OR of a byte of the MONDA register. Array index i corresponds to byte i of the MONDA register."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_a_0(&mut self) -> NewDatA0W<MsghandgrpMondxSpec> {
        NewDatA0W::new(self, 0)
    }
    #[doc = "Bit 1 - Each bit in this field is a logical OR of a byte of the MONDA register. Array index i corresponds to byte i of the MONDA register."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_a_1(&mut self) -> NewDatA1W<MsghandgrpMondxSpec> {
        NewDatA1W::new(self, 1)
    }
    #[doc = "Bit 2 - Each bit in this field is a logical OR of a byte of the MONDA register. Array index i corresponds to byte i of the MONDA register."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_a_2(&mut self) -> NewDatA2W<MsghandgrpMondxSpec> {
        NewDatA2W::new(self, 2)
    }
    #[doc = "Bit 3 - Each bit in this field is a logical OR of a byte of the MONDA register. Array index i corresponds to byte i of the MONDA register."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_a_3(&mut self) -> NewDatA3W<MsghandgrpMondxSpec> {
        NewDatA3W::new(self, 3)
    }
    #[doc = "Bit 4 - Each bit in this field is a logical OR of a byte of the MONDB register. Array index i corresponds to byte i of the MONDB register."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_b_0(&mut self) -> NewDatB0W<MsghandgrpMondxSpec> {
        NewDatB0W::new(self, 4)
    }
    #[doc = "Bit 5 - Each bit in this field is a logical OR of a byte of the MONDB register. Array index i corresponds to byte i of the MONDB register."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_b_1(&mut self) -> NewDatB1W<MsghandgrpMondxSpec> {
        NewDatB1W::new(self, 5)
    }
    #[doc = "Bit 6 - Each bit in this field is a logical OR of a byte of the MONDB register. Array index i corresponds to byte i of the MONDB register."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_b_2(&mut self) -> NewDatB2W<MsghandgrpMondxSpec> {
        NewDatB2W::new(self, 6)
    }
    #[doc = "Bit 7 - Each bit in this field is a logical OR of a byte of the MONDB register. Array index i corresponds to byte i of the MONDB register."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_b_3(&mut self) -> NewDatB3W<MsghandgrpMondxSpec> {
        NewDatB3W::new(self, 7)
    }
    #[doc = "Bit 8 - Each bit in this field is a logical OR of a byte of the MONDC register. Array index i corresponds to byte i of the MONDC register."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_c_0(&mut self) -> NewDatC0W<MsghandgrpMondxSpec> {
        NewDatC0W::new(self, 8)
    }
    #[doc = "Bit 9 - Each bit in this field is a logical OR of a byte of the MONDC register. Array index i corresponds to byte i of the MONDC register."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_c_1(&mut self) -> NewDatC1W<MsghandgrpMondxSpec> {
        NewDatC1W::new(self, 9)
    }
    #[doc = "Bit 10 - Each bit in this field is a logical OR of a byte of the MONDC register. Array index i corresponds to byte i of the MONDC register."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_c_2(&mut self) -> NewDatC2W<MsghandgrpMondxSpec> {
        NewDatC2W::new(self, 10)
    }
    #[doc = "Bit 11 - Each bit in this field is a logical OR of a byte of the MONDC register. Array index i corresponds to byte i of the MONDC register."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_c_3(&mut self) -> NewDatC3W<MsghandgrpMondxSpec> {
        NewDatC3W::new(self, 11)
    }
    #[doc = "Bit 12 - Each bit in this field is a logical OR of a byte of the MONDD register. Array index i corresponds to byte i of the MONDD register."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_d_0(&mut self) -> NewDatD0W<MsghandgrpMondxSpec> {
        NewDatD0W::new(self, 12)
    }
    #[doc = "Bit 13 - Each bit in this field is a logical OR of a byte of the MONDD register. Array index i corresponds to byte i of the MONDD register."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_d_1(&mut self) -> NewDatD1W<MsghandgrpMondxSpec> {
        NewDatD1W::new(self, 13)
    }
    #[doc = "Bit 14 - Each bit in this field is a logical OR of a byte of the MONDD register. Array index i corresponds to byte i of the MONDD register."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_d_2(&mut self) -> NewDatD2W<MsghandgrpMondxSpec> {
        NewDatD2W::new(self, 14)
    }
    #[doc = "Bit 15 - Each bit in this field is a logical OR of a byte of the MONDD register. Array index i corresponds to byte i of the MONDD register."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_d_3(&mut self) -> NewDatD3W<MsghandgrpMondxSpec> {
        NewDatD3W::new(self, 15)
    }
}
#[doc = "Reading this register allows the CPU to quickly detect if any of the new data bits in each of the MONDA, MONDB, MONDC, and MONDD New Data Registers are set.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_mondx::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MsghandgrpMondxSpec;
impl crate::RegisterSpec for MsghandgrpMondxSpec {
    type Ux = u32;
    const OFFSET: u64 = 152u64;
}
#[doc = "`read()` method returns [`msghandgrp_mondx::R`](R) reader structure"]
impl crate::Readable for MsghandgrpMondxSpec {}
#[doc = "`reset()` method sets msghandgrp_MONDX to value 0"]
impl crate::Resettable for MsghandgrpMondxSpec {
    const RESET_VALUE: u32 = 0;
}
