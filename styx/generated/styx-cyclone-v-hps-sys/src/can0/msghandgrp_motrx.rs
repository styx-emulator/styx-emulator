// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `msghandgrp_MOTRX` reader"]
pub type R = crate::R<MsghandgrpMotrxSpec>;
#[doc = "Register `msghandgrp_MOTRX` writer"]
pub type W = crate::W<MsghandgrpMotrxSpec>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOTRA register. Array index i corresponds to byte i of the MOTRA register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqstA0 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqstA0> for bool {
    #[inline(always)]
    fn from(variant: TxRqstA0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqstA_0` reader - Each bit in this field is a logical OR of a byte of the MOTRA register. Array index i corresponds to byte i of the MOTRA register."]
pub type TxRqstA0R = crate::BitReader<TxRqstA0>;
impl TxRqstA0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqstA0 {
        match self.bits {
            false => TxRqstA0::NotWaiting,
            true => TxRqstA0::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqstA0::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqstA0::Pending
    }
}
#[doc = "Field `TxRqstA_0` writer - Each bit in this field is a logical OR of a byte of the MOTRA register. Array index i corresponds to byte i of the MOTRA register."]
pub type TxRqstA0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOTRA register. Array index i corresponds to byte i of the MOTRA register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqstA1 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqstA1> for bool {
    #[inline(always)]
    fn from(variant: TxRqstA1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqstA_1` reader - Each bit in this field is a logical OR of a byte of the MOTRA register. Array index i corresponds to byte i of the MOTRA register."]
pub type TxRqstA1R = crate::BitReader<TxRqstA1>;
impl TxRqstA1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqstA1 {
        match self.bits {
            false => TxRqstA1::NotWaiting,
            true => TxRqstA1::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqstA1::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqstA1::Pending
    }
}
#[doc = "Field `TxRqstA_1` writer - Each bit in this field is a logical OR of a byte of the MOTRA register. Array index i corresponds to byte i of the MOTRA register."]
pub type TxRqstA1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOTRA register. Array index i corresponds to byte i of the MOTRA register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqstA2 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqstA2> for bool {
    #[inline(always)]
    fn from(variant: TxRqstA2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqstA_2` reader - Each bit in this field is a logical OR of a byte of the MOTRA register. Array index i corresponds to byte i of the MOTRA register."]
pub type TxRqstA2R = crate::BitReader<TxRqstA2>;
impl TxRqstA2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqstA2 {
        match self.bits {
            false => TxRqstA2::NotWaiting,
            true => TxRqstA2::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqstA2::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqstA2::Pending
    }
}
#[doc = "Field `TxRqstA_2` writer - Each bit in this field is a logical OR of a byte of the MOTRA register. Array index i corresponds to byte i of the MOTRA register."]
pub type TxRqstA2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOTRA register. Array index i corresponds to byte i of the MOTRA register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqstA3 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqstA3> for bool {
    #[inline(always)]
    fn from(variant: TxRqstA3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqstA_3` reader - Each bit in this field is a logical OR of a byte of the MOTRA register. Array index i corresponds to byte i of the MOTRA register."]
pub type TxRqstA3R = crate::BitReader<TxRqstA3>;
impl TxRqstA3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqstA3 {
        match self.bits {
            false => TxRqstA3::NotWaiting,
            true => TxRqstA3::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqstA3::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqstA3::Pending
    }
}
#[doc = "Field `TxRqstA_3` writer - Each bit in this field is a logical OR of a byte of the MOTRA register. Array index i corresponds to byte i of the MOTRA register."]
pub type TxRqstA3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOTRB register. Array index i corresponds to byte i of the MOTRB register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqstB0 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqstB0> for bool {
    #[inline(always)]
    fn from(variant: TxRqstB0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqstB_0` reader - Each bit in this field is a logical OR of a byte of the MOTRB register. Array index i corresponds to byte i of the MOTRB register."]
pub type TxRqstB0R = crate::BitReader<TxRqstB0>;
impl TxRqstB0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqstB0 {
        match self.bits {
            false => TxRqstB0::NotWaiting,
            true => TxRqstB0::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqstB0::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqstB0::Pending
    }
}
#[doc = "Field `TxRqstB_0` writer - Each bit in this field is a logical OR of a byte of the MOTRB register. Array index i corresponds to byte i of the MOTRB register."]
pub type TxRqstB0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOTRB register. Array index i corresponds to byte i of the MOTRB register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqstB1 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqstB1> for bool {
    #[inline(always)]
    fn from(variant: TxRqstB1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqstB_1` reader - Each bit in this field is a logical OR of a byte of the MOTRB register. Array index i corresponds to byte i of the MOTRB register."]
pub type TxRqstB1R = crate::BitReader<TxRqstB1>;
impl TxRqstB1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqstB1 {
        match self.bits {
            false => TxRqstB1::NotWaiting,
            true => TxRqstB1::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqstB1::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqstB1::Pending
    }
}
#[doc = "Field `TxRqstB_1` writer - Each bit in this field is a logical OR of a byte of the MOTRB register. Array index i corresponds to byte i of the MOTRB register."]
pub type TxRqstB1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOTRB register. Array index i corresponds to byte i of the MOTRB register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqstB2 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqstB2> for bool {
    #[inline(always)]
    fn from(variant: TxRqstB2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqstB_2` reader - Each bit in this field is a logical OR of a byte of the MOTRB register. Array index i corresponds to byte i of the MOTRB register."]
pub type TxRqstB2R = crate::BitReader<TxRqstB2>;
impl TxRqstB2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqstB2 {
        match self.bits {
            false => TxRqstB2::NotWaiting,
            true => TxRqstB2::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqstB2::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqstB2::Pending
    }
}
#[doc = "Field `TxRqstB_2` writer - Each bit in this field is a logical OR of a byte of the MOTRB register. Array index i corresponds to byte i of the MOTRB register."]
pub type TxRqstB2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOTRB register. Array index i corresponds to byte i of the MOTRB register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqstB3 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqstB3> for bool {
    #[inline(always)]
    fn from(variant: TxRqstB3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqstB_3` reader - Each bit in this field is a logical OR of a byte of the MOTRB register. Array index i corresponds to byte i of the MOTRB register."]
pub type TxRqstB3R = crate::BitReader<TxRqstB3>;
impl TxRqstB3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqstB3 {
        match self.bits {
            false => TxRqstB3::NotWaiting,
            true => TxRqstB3::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqstB3::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqstB3::Pending
    }
}
#[doc = "Field `TxRqstB_3` writer - Each bit in this field is a logical OR of a byte of the MOTRB register. Array index i corresponds to byte i of the MOTRB register."]
pub type TxRqstB3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOTRC register. Array index i corresponds to byte i of the MOTRC register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqstC0 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqstC0> for bool {
    #[inline(always)]
    fn from(variant: TxRqstC0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqstC_0` reader - Each bit in this field is a logical OR of a byte of the MOTRC register. Array index i corresponds to byte i of the MOTRC register."]
pub type TxRqstC0R = crate::BitReader<TxRqstC0>;
impl TxRqstC0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqstC0 {
        match self.bits {
            false => TxRqstC0::NotWaiting,
            true => TxRqstC0::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqstC0::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqstC0::Pending
    }
}
#[doc = "Field `TxRqstC_0` writer - Each bit in this field is a logical OR of a byte of the MOTRC register. Array index i corresponds to byte i of the MOTRC register."]
pub type TxRqstC0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOTRC register. Array index i corresponds to byte i of the MOTRC register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqstC1 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqstC1> for bool {
    #[inline(always)]
    fn from(variant: TxRqstC1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqstC_1` reader - Each bit in this field is a logical OR of a byte of the MOTRC register. Array index i corresponds to byte i of the MOTRC register."]
pub type TxRqstC1R = crate::BitReader<TxRqstC1>;
impl TxRqstC1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqstC1 {
        match self.bits {
            false => TxRqstC1::NotWaiting,
            true => TxRqstC1::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqstC1::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqstC1::Pending
    }
}
#[doc = "Field `TxRqstC_1` writer - Each bit in this field is a logical OR of a byte of the MOTRC register. Array index i corresponds to byte i of the MOTRC register."]
pub type TxRqstC1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOTRC register. Array index i corresponds to byte i of the MOTRC register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqstC2 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqstC2> for bool {
    #[inline(always)]
    fn from(variant: TxRqstC2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqstC_2` reader - Each bit in this field is a logical OR of a byte of the MOTRC register. Array index i corresponds to byte i of the MOTRC register."]
pub type TxRqstC2R = crate::BitReader<TxRqstC2>;
impl TxRqstC2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqstC2 {
        match self.bits {
            false => TxRqstC2::NotWaiting,
            true => TxRqstC2::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqstC2::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqstC2::Pending
    }
}
#[doc = "Field `TxRqstC_2` writer - Each bit in this field is a logical OR of a byte of the MOTRC register. Array index i corresponds to byte i of the MOTRC register."]
pub type TxRqstC2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOTRC register. Array index i corresponds to byte i of the MOTRC register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqstC3 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqstC3> for bool {
    #[inline(always)]
    fn from(variant: TxRqstC3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqstC_3` reader - Each bit in this field is a logical OR of a byte of the MOTRC register. Array index i corresponds to byte i of the MOTRC register."]
pub type TxRqstC3R = crate::BitReader<TxRqstC3>;
impl TxRqstC3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqstC3 {
        match self.bits {
            false => TxRqstC3::NotWaiting,
            true => TxRqstC3::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqstC3::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqstC3::Pending
    }
}
#[doc = "Field `TxRqstC_3` writer - Each bit in this field is a logical OR of a byte of the MOTRC register. Array index i corresponds to byte i of the MOTRC register."]
pub type TxRqstC3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOTRD register. Array index i corresponds to byte i of the MOTRD register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqstD0 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqstD0> for bool {
    #[inline(always)]
    fn from(variant: TxRqstD0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqstD_0` reader - Each bit in this field is a logical OR of a byte of the MOTRD register. Array index i corresponds to byte i of the MOTRD register."]
pub type TxRqstD0R = crate::BitReader<TxRqstD0>;
impl TxRqstD0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqstD0 {
        match self.bits {
            false => TxRqstD0::NotWaiting,
            true => TxRqstD0::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqstD0::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqstD0::Pending
    }
}
#[doc = "Field `TxRqstD_0` writer - Each bit in this field is a logical OR of a byte of the MOTRD register. Array index i corresponds to byte i of the MOTRD register."]
pub type TxRqstD0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOTRD register. Array index i corresponds to byte i of the MOTRD register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqstD1 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqstD1> for bool {
    #[inline(always)]
    fn from(variant: TxRqstD1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqstD_1` reader - Each bit in this field is a logical OR of a byte of the MOTRD register. Array index i corresponds to byte i of the MOTRD register."]
pub type TxRqstD1R = crate::BitReader<TxRqstD1>;
impl TxRqstD1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqstD1 {
        match self.bits {
            false => TxRqstD1::NotWaiting,
            true => TxRqstD1::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqstD1::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqstD1::Pending
    }
}
#[doc = "Field `TxRqstD_1` writer - Each bit in this field is a logical OR of a byte of the MOTRD register. Array index i corresponds to byte i of the MOTRD register."]
pub type TxRqstD1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOTRD register. Array index i corresponds to byte i of the MOTRD register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqstD2 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqstD2> for bool {
    #[inline(always)]
    fn from(variant: TxRqstD2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqstD_2` reader - Each bit in this field is a logical OR of a byte of the MOTRD register. Array index i corresponds to byte i of the MOTRD register."]
pub type TxRqstD2R = crate::BitReader<TxRqstD2>;
impl TxRqstD2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqstD2 {
        match self.bits {
            false => TxRqstD2::NotWaiting,
            true => TxRqstD2::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqstD2::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqstD2::Pending
    }
}
#[doc = "Field `TxRqstD_2` writer - Each bit in this field is a logical OR of a byte of the MOTRD register. Array index i corresponds to byte i of the MOTRD register."]
pub type TxRqstD2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOTRD register. Array index i corresponds to byte i of the MOTRD register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqstD3 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqstD3> for bool {
    #[inline(always)]
    fn from(variant: TxRqstD3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqstD_3` reader - Each bit in this field is a logical OR of a byte of the MOTRD register. Array index i corresponds to byte i of the MOTRD register."]
pub type TxRqstD3R = crate::BitReader<TxRqstD3>;
impl TxRqstD3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqstD3 {
        match self.bits {
            false => TxRqstD3::NotWaiting,
            true => TxRqstD3::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqstD3::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqstD3::Pending
    }
}
#[doc = "Field `TxRqstD_3` writer - Each bit in this field is a logical OR of a byte of the MOTRD register. Array index i corresponds to byte i of the MOTRD register."]
pub type TxRqstD3W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Each bit in this field is a logical OR of a byte of the MOTRA register. Array index i corresponds to byte i of the MOTRA register."]
    #[inline(always)]
    pub fn tx_rqst_a_0(&self) -> TxRqstA0R {
        TxRqstA0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Each bit in this field is a logical OR of a byte of the MOTRA register. Array index i corresponds to byte i of the MOTRA register."]
    #[inline(always)]
    pub fn tx_rqst_a_1(&self) -> TxRqstA1R {
        TxRqstA1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Each bit in this field is a logical OR of a byte of the MOTRA register. Array index i corresponds to byte i of the MOTRA register."]
    #[inline(always)]
    pub fn tx_rqst_a_2(&self) -> TxRqstA2R {
        TxRqstA2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Each bit in this field is a logical OR of a byte of the MOTRA register. Array index i corresponds to byte i of the MOTRA register."]
    #[inline(always)]
    pub fn tx_rqst_a_3(&self) -> TxRqstA3R {
        TxRqstA3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Each bit in this field is a logical OR of a byte of the MOTRB register. Array index i corresponds to byte i of the MOTRB register."]
    #[inline(always)]
    pub fn tx_rqst_b_0(&self) -> TxRqstB0R {
        TxRqstB0R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Each bit in this field is a logical OR of a byte of the MOTRB register. Array index i corresponds to byte i of the MOTRB register."]
    #[inline(always)]
    pub fn tx_rqst_b_1(&self) -> TxRqstB1R {
        TxRqstB1R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Each bit in this field is a logical OR of a byte of the MOTRB register. Array index i corresponds to byte i of the MOTRB register."]
    #[inline(always)]
    pub fn tx_rqst_b_2(&self) -> TxRqstB2R {
        TxRqstB2R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Each bit in this field is a logical OR of a byte of the MOTRB register. Array index i corresponds to byte i of the MOTRB register."]
    #[inline(always)]
    pub fn tx_rqst_b_3(&self) -> TxRqstB3R {
        TxRqstB3R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Each bit in this field is a logical OR of a byte of the MOTRC register. Array index i corresponds to byte i of the MOTRC register."]
    #[inline(always)]
    pub fn tx_rqst_c_0(&self) -> TxRqstC0R {
        TxRqstC0R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Each bit in this field is a logical OR of a byte of the MOTRC register. Array index i corresponds to byte i of the MOTRC register."]
    #[inline(always)]
    pub fn tx_rqst_c_1(&self) -> TxRqstC1R {
        TxRqstC1R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Each bit in this field is a logical OR of a byte of the MOTRC register. Array index i corresponds to byte i of the MOTRC register."]
    #[inline(always)]
    pub fn tx_rqst_c_2(&self) -> TxRqstC2R {
        TxRqstC2R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Each bit in this field is a logical OR of a byte of the MOTRC register. Array index i corresponds to byte i of the MOTRC register."]
    #[inline(always)]
    pub fn tx_rqst_c_3(&self) -> TxRqstC3R {
        TxRqstC3R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Each bit in this field is a logical OR of a byte of the MOTRD register. Array index i corresponds to byte i of the MOTRD register."]
    #[inline(always)]
    pub fn tx_rqst_d_0(&self) -> TxRqstD0R {
        TxRqstD0R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Each bit in this field is a logical OR of a byte of the MOTRD register. Array index i corresponds to byte i of the MOTRD register."]
    #[inline(always)]
    pub fn tx_rqst_d_1(&self) -> TxRqstD1R {
        TxRqstD1R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Each bit in this field is a logical OR of a byte of the MOTRD register. Array index i corresponds to byte i of the MOTRD register."]
    #[inline(always)]
    pub fn tx_rqst_d_2(&self) -> TxRqstD2R {
        TxRqstD2R::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Each bit in this field is a logical OR of a byte of the MOTRD register. Array index i corresponds to byte i of the MOTRD register."]
    #[inline(always)]
    pub fn tx_rqst_d_3(&self) -> TxRqstD3R {
        TxRqstD3R::new(((self.bits >> 15) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Each bit in this field is a logical OR of a byte of the MOTRA register. Array index i corresponds to byte i of the MOTRA register."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_a_0(&mut self) -> TxRqstA0W<MsghandgrpMotrxSpec> {
        TxRqstA0W::new(self, 0)
    }
    #[doc = "Bit 1 - Each bit in this field is a logical OR of a byte of the MOTRA register. Array index i corresponds to byte i of the MOTRA register."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_a_1(&mut self) -> TxRqstA1W<MsghandgrpMotrxSpec> {
        TxRqstA1W::new(self, 1)
    }
    #[doc = "Bit 2 - Each bit in this field is a logical OR of a byte of the MOTRA register. Array index i corresponds to byte i of the MOTRA register."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_a_2(&mut self) -> TxRqstA2W<MsghandgrpMotrxSpec> {
        TxRqstA2W::new(self, 2)
    }
    #[doc = "Bit 3 - Each bit in this field is a logical OR of a byte of the MOTRA register. Array index i corresponds to byte i of the MOTRA register."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_a_3(&mut self) -> TxRqstA3W<MsghandgrpMotrxSpec> {
        TxRqstA3W::new(self, 3)
    }
    #[doc = "Bit 4 - Each bit in this field is a logical OR of a byte of the MOTRB register. Array index i corresponds to byte i of the MOTRB register."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_b_0(&mut self) -> TxRqstB0W<MsghandgrpMotrxSpec> {
        TxRqstB0W::new(self, 4)
    }
    #[doc = "Bit 5 - Each bit in this field is a logical OR of a byte of the MOTRB register. Array index i corresponds to byte i of the MOTRB register."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_b_1(&mut self) -> TxRqstB1W<MsghandgrpMotrxSpec> {
        TxRqstB1W::new(self, 5)
    }
    #[doc = "Bit 6 - Each bit in this field is a logical OR of a byte of the MOTRB register. Array index i corresponds to byte i of the MOTRB register."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_b_2(&mut self) -> TxRqstB2W<MsghandgrpMotrxSpec> {
        TxRqstB2W::new(self, 6)
    }
    #[doc = "Bit 7 - Each bit in this field is a logical OR of a byte of the MOTRB register. Array index i corresponds to byte i of the MOTRB register."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_b_3(&mut self) -> TxRqstB3W<MsghandgrpMotrxSpec> {
        TxRqstB3W::new(self, 7)
    }
    #[doc = "Bit 8 - Each bit in this field is a logical OR of a byte of the MOTRC register. Array index i corresponds to byte i of the MOTRC register."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_c_0(&mut self) -> TxRqstC0W<MsghandgrpMotrxSpec> {
        TxRqstC0W::new(self, 8)
    }
    #[doc = "Bit 9 - Each bit in this field is a logical OR of a byte of the MOTRC register. Array index i corresponds to byte i of the MOTRC register."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_c_1(&mut self) -> TxRqstC1W<MsghandgrpMotrxSpec> {
        TxRqstC1W::new(self, 9)
    }
    #[doc = "Bit 10 - Each bit in this field is a logical OR of a byte of the MOTRC register. Array index i corresponds to byte i of the MOTRC register."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_c_2(&mut self) -> TxRqstC2W<MsghandgrpMotrxSpec> {
        TxRqstC2W::new(self, 10)
    }
    #[doc = "Bit 11 - Each bit in this field is a logical OR of a byte of the MOTRC register. Array index i corresponds to byte i of the MOTRC register."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_c_3(&mut self) -> TxRqstC3W<MsghandgrpMotrxSpec> {
        TxRqstC3W::new(self, 11)
    }
    #[doc = "Bit 12 - Each bit in this field is a logical OR of a byte of the MOTRD register. Array index i corresponds to byte i of the MOTRD register."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_d_0(&mut self) -> TxRqstD0W<MsghandgrpMotrxSpec> {
        TxRqstD0W::new(self, 12)
    }
    #[doc = "Bit 13 - Each bit in this field is a logical OR of a byte of the MOTRD register. Array index i corresponds to byte i of the MOTRD register."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_d_1(&mut self) -> TxRqstD1W<MsghandgrpMotrxSpec> {
        TxRqstD1W::new(self, 13)
    }
    #[doc = "Bit 14 - Each bit in this field is a logical OR of a byte of the MOTRD register. Array index i corresponds to byte i of the MOTRD register."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_d_2(&mut self) -> TxRqstD2W<MsghandgrpMotrxSpec> {
        TxRqstD2W::new(self, 14)
    }
    #[doc = "Bit 15 - Each bit in this field is a logical OR of a byte of the MOTRD register. Array index i corresponds to byte i of the MOTRD register."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_d_3(&mut self) -> TxRqstD3W<MsghandgrpMotrxSpec> {
        TxRqstD3W::new(self, 15)
    }
}
#[doc = "Reading this register allows the CPU to quickly detect if any of the transmission request bits in each of the MOTRA, MOTRB, MOTRC, and MOTRD Transmission Request Registers are set.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_motrx::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MsghandgrpMotrxSpec;
impl crate::RegisterSpec for MsghandgrpMotrxSpec {
    type Ux = u32;
    const OFFSET: u64 = 132u64;
}
#[doc = "`read()` method returns [`msghandgrp_motrx::R`](R) reader structure"]
impl crate::Readable for MsghandgrpMotrxSpec {}
#[doc = "`reset()` method sets msghandgrp_MOTRX to value 0"]
impl crate::Resettable for MsghandgrpMotrxSpec {
    const RESET_VALUE: u32 = 0;
}
