// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `msghandgrp_MONDB` reader"]
pub type R = crate::R<MsghandgrpMondbSpec>;
#[doc = "Register `msghandgrp_MONDB` writer"]
pub type W = crate::W<MsghandgrpMondbSpec>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat0 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat0> for bool {
    #[inline(always)]
    fn from(variant: NewDat0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_0` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat0R = crate::BitReader<NewDat0>;
impl NewDat0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat0 {
        match self.bits {
            false => NewDat0::NotWritten,
            true => NewDat0::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat0::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat0::Written
    }
}
#[doc = "Field `NewDat_0` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat1 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat1> for bool {
    #[inline(always)]
    fn from(variant: NewDat1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_1` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat1R = crate::BitReader<NewDat1>;
impl NewDat1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat1 {
        match self.bits {
            false => NewDat1::NotWritten,
            true => NewDat1::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat1::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat1::Written
    }
}
#[doc = "Field `NewDat_1` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat2 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat2> for bool {
    #[inline(always)]
    fn from(variant: NewDat2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_2` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat2R = crate::BitReader<NewDat2>;
impl NewDat2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat2 {
        match self.bits {
            false => NewDat2::NotWritten,
            true => NewDat2::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat2::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat2::Written
    }
}
#[doc = "Field `NewDat_2` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat3 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat3> for bool {
    #[inline(always)]
    fn from(variant: NewDat3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_3` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat3R = crate::BitReader<NewDat3>;
impl NewDat3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat3 {
        match self.bits {
            false => NewDat3::NotWritten,
            true => NewDat3::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat3::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat3::Written
    }
}
#[doc = "Field `NewDat_3` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat4 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat4> for bool {
    #[inline(always)]
    fn from(variant: NewDat4) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_4` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat4R = crate::BitReader<NewDat4>;
impl NewDat4R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat4 {
        match self.bits {
            false => NewDat4::NotWritten,
            true => NewDat4::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat4::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat4::Written
    }
}
#[doc = "Field `NewDat_4` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat5 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat5> for bool {
    #[inline(always)]
    fn from(variant: NewDat5) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_5` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat5R = crate::BitReader<NewDat5>;
impl NewDat5R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat5 {
        match self.bits {
            false => NewDat5::NotWritten,
            true => NewDat5::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat5::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat5::Written
    }
}
#[doc = "Field `NewDat_5` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat6 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat6> for bool {
    #[inline(always)]
    fn from(variant: NewDat6) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_6` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat6R = crate::BitReader<NewDat6>;
impl NewDat6R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat6 {
        match self.bits {
            false => NewDat6::NotWritten,
            true => NewDat6::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat6::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat6::Written
    }
}
#[doc = "Field `NewDat_6` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat7 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat7> for bool {
    #[inline(always)]
    fn from(variant: NewDat7) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_7` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat7R = crate::BitReader<NewDat7>;
impl NewDat7R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat7 {
        match self.bits {
            false => NewDat7::NotWritten,
            true => NewDat7::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat7::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat7::Written
    }
}
#[doc = "Field `NewDat_7` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat7W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat8 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat8> for bool {
    #[inline(always)]
    fn from(variant: NewDat8) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_8` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat8R = crate::BitReader<NewDat8>;
impl NewDat8R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat8 {
        match self.bits {
            false => NewDat8::NotWritten,
            true => NewDat8::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat8::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat8::Written
    }
}
#[doc = "Field `NewDat_8` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat8W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat9 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat9> for bool {
    #[inline(always)]
    fn from(variant: NewDat9) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_9` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat9R = crate::BitReader<NewDat9>;
impl NewDat9R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat9 {
        match self.bits {
            false => NewDat9::NotWritten,
            true => NewDat9::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat9::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat9::Written
    }
}
#[doc = "Field `NewDat_9` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat9W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat10 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat10> for bool {
    #[inline(always)]
    fn from(variant: NewDat10) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_10` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat10R = crate::BitReader<NewDat10>;
impl NewDat10R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat10 {
        match self.bits {
            false => NewDat10::NotWritten,
            true => NewDat10::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat10::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat10::Written
    }
}
#[doc = "Field `NewDat_10` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat10W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat11 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat11> for bool {
    #[inline(always)]
    fn from(variant: NewDat11) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_11` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat11R = crate::BitReader<NewDat11>;
impl NewDat11R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat11 {
        match self.bits {
            false => NewDat11::NotWritten,
            true => NewDat11::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat11::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat11::Written
    }
}
#[doc = "Field `NewDat_11` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat11W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat12 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat12> for bool {
    #[inline(always)]
    fn from(variant: NewDat12) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_12` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat12R = crate::BitReader<NewDat12>;
impl NewDat12R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat12 {
        match self.bits {
            false => NewDat12::NotWritten,
            true => NewDat12::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat12::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat12::Written
    }
}
#[doc = "Field `NewDat_12` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat12W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat13 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat13> for bool {
    #[inline(always)]
    fn from(variant: NewDat13) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_13` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat13R = crate::BitReader<NewDat13>;
impl NewDat13R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat13 {
        match self.bits {
            false => NewDat13::NotWritten,
            true => NewDat13::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat13::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat13::Written
    }
}
#[doc = "Field `NewDat_13` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat13W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat14 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat14> for bool {
    #[inline(always)]
    fn from(variant: NewDat14) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_14` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat14R = crate::BitReader<NewDat14>;
impl NewDat14R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat14 {
        match self.bits {
            false => NewDat14::NotWritten,
            true => NewDat14::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat14::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat14::Written
    }
}
#[doc = "Field `NewDat_14` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat14W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat15 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat15> for bool {
    #[inline(always)]
    fn from(variant: NewDat15) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_15` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat15R = crate::BitReader<NewDat15>;
impl NewDat15R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat15 {
        match self.bits {
            false => NewDat15::NotWritten,
            true => NewDat15::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat15::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat15::Written
    }
}
#[doc = "Field `NewDat_15` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat15W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat16 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat16> for bool {
    #[inline(always)]
    fn from(variant: NewDat16) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_16` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat16R = crate::BitReader<NewDat16>;
impl NewDat16R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat16 {
        match self.bits {
            false => NewDat16::NotWritten,
            true => NewDat16::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat16::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat16::Written
    }
}
#[doc = "Field `NewDat_16` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat16W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat17 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat17> for bool {
    #[inline(always)]
    fn from(variant: NewDat17) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_17` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat17R = crate::BitReader<NewDat17>;
impl NewDat17R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat17 {
        match self.bits {
            false => NewDat17::NotWritten,
            true => NewDat17::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat17::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat17::Written
    }
}
#[doc = "Field `NewDat_17` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat17W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat18 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat18> for bool {
    #[inline(always)]
    fn from(variant: NewDat18) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_18` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat18R = crate::BitReader<NewDat18>;
impl NewDat18R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat18 {
        match self.bits {
            false => NewDat18::NotWritten,
            true => NewDat18::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat18::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat18::Written
    }
}
#[doc = "Field `NewDat_18` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat18W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat19 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat19> for bool {
    #[inline(always)]
    fn from(variant: NewDat19) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_19` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat19R = crate::BitReader<NewDat19>;
impl NewDat19R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat19 {
        match self.bits {
            false => NewDat19::NotWritten,
            true => NewDat19::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat19::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat19::Written
    }
}
#[doc = "Field `NewDat_19` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat19W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat20 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat20> for bool {
    #[inline(always)]
    fn from(variant: NewDat20) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_20` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat20R = crate::BitReader<NewDat20>;
impl NewDat20R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat20 {
        match self.bits {
            false => NewDat20::NotWritten,
            true => NewDat20::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat20::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat20::Written
    }
}
#[doc = "Field `NewDat_20` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat20W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat21 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat21> for bool {
    #[inline(always)]
    fn from(variant: NewDat21) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_21` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat21R = crate::BitReader<NewDat21>;
impl NewDat21R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat21 {
        match self.bits {
            false => NewDat21::NotWritten,
            true => NewDat21::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat21::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat21::Written
    }
}
#[doc = "Field `NewDat_21` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat21W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat22 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat22> for bool {
    #[inline(always)]
    fn from(variant: NewDat22) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_22` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat22R = crate::BitReader<NewDat22>;
impl NewDat22R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat22 {
        match self.bits {
            false => NewDat22::NotWritten,
            true => NewDat22::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat22::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat22::Written
    }
}
#[doc = "Field `NewDat_22` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat22W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat23 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat23> for bool {
    #[inline(always)]
    fn from(variant: NewDat23) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_23` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat23R = crate::BitReader<NewDat23>;
impl NewDat23R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat23 {
        match self.bits {
            false => NewDat23::NotWritten,
            true => NewDat23::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat23::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat23::Written
    }
}
#[doc = "Field `NewDat_23` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat23W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat24 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat24> for bool {
    #[inline(always)]
    fn from(variant: NewDat24) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_24` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat24R = crate::BitReader<NewDat24>;
impl NewDat24R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat24 {
        match self.bits {
            false => NewDat24::NotWritten,
            true => NewDat24::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat24::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat24::Written
    }
}
#[doc = "Field `NewDat_24` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat24W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat25 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat25> for bool {
    #[inline(always)]
    fn from(variant: NewDat25) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_25` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat25R = crate::BitReader<NewDat25>;
impl NewDat25R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat25 {
        match self.bits {
            false => NewDat25::NotWritten,
            true => NewDat25::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat25::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat25::Written
    }
}
#[doc = "Field `NewDat_25` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat25W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat26 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat26> for bool {
    #[inline(always)]
    fn from(variant: NewDat26) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_26` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat26R = crate::BitReader<NewDat26>;
impl NewDat26R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat26 {
        match self.bits {
            false => NewDat26::NotWritten,
            true => NewDat26::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat26::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat26::Written
    }
}
#[doc = "Field `NewDat_26` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat26W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat27 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat27> for bool {
    #[inline(always)]
    fn from(variant: NewDat27) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_27` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat27R = crate::BitReader<NewDat27>;
impl NewDat27R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat27 {
        match self.bits {
            false => NewDat27::NotWritten,
            true => NewDat27::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat27::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat27::Written
    }
}
#[doc = "Field `NewDat_27` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat27W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat28 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat28> for bool {
    #[inline(always)]
    fn from(variant: NewDat28) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_28` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat28R = crate::BitReader<NewDat28>;
impl NewDat28R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat28 {
        match self.bits {
            false => NewDat28::NotWritten,
            true => NewDat28::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat28::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat28::Written
    }
}
#[doc = "Field `NewDat_28` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat28W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat29 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat29> for bool {
    #[inline(always)]
    fn from(variant: NewDat29) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_29` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat29R = crate::BitReader<NewDat29>;
impl NewDat29R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat29 {
        match self.bits {
            false => NewDat29::NotWritten,
            true => NewDat29::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat29::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat29::Written
    }
}
#[doc = "Field `NewDat_29` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat29W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat30 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat30> for bool {
    #[inline(always)]
    fn from(variant: NewDat30) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_30` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat30R = crate::BitReader<NewDat30>;
impl NewDat30R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat30 {
        match self.bits {
            false => NewDat30::NotWritten,
            true => NewDat30::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat30::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat30::Written
    }
}
#[doc = "Field `NewDat_30` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat30W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewDat31 {
    #[doc = "0: `0`"]
    NotWritten = 0,
    #[doc = "1: `1`"]
    Written = 1,
}
impl From<NewDat31> for bool {
    #[inline(always)]
    fn from(variant: NewDat31) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `NewDat_31` reader - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat31R = crate::BitReader<NewDat31>;
impl NewDat31R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> NewDat31 {
        match self.bits {
            false => NewDat31::NotWritten,
            true => NewDat31::Written,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_written(&self) -> bool {
        *self == NewDat31::NotWritten
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_written(&self) -> bool {
        *self == NewDat31::Written
    }
}
#[doc = "Field `NewDat_31` writer - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
pub type NewDat31W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_0(&self) -> NewDat0R {
        NewDat0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_1(&self) -> NewDat1R {
        NewDat1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_2(&self) -> NewDat2R {
        NewDat2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_3(&self) -> NewDat3R {
        NewDat3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_4(&self) -> NewDat4R {
        NewDat4R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_5(&self) -> NewDat5R {
        NewDat5R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_6(&self) -> NewDat6R {
        NewDat6R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_7(&self) -> NewDat7R {
        NewDat7R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_8(&self) -> NewDat8R {
        NewDat8R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_9(&self) -> NewDat9R {
        NewDat9R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_10(&self) -> NewDat10R {
        NewDat10R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_11(&self) -> NewDat11R {
        NewDat11R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_12(&self) -> NewDat12R {
        NewDat12R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_13(&self) -> NewDat13R {
        NewDat13R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_14(&self) -> NewDat14R {
        NewDat14R::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_15(&self) -> NewDat15R {
        NewDat15R::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_16(&self) -> NewDat16R {
        NewDat16R::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_17(&self) -> NewDat17R {
        NewDat17R::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_18(&self) -> NewDat18R {
        NewDat18R::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_19(&self) -> NewDat19R {
        NewDat19R::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_20(&self) -> NewDat20R {
        NewDat20R::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_21(&self) -> NewDat21R {
        NewDat21R::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_22(&self) -> NewDat22R {
        NewDat22R::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_23(&self) -> NewDat23R {
        NewDat23R::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_24(&self) -> NewDat24R {
        NewDat24R::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_25(&self) -> NewDat25R {
        NewDat25R::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_26(&self) -> NewDat26R {
        NewDat26R::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_27(&self) -> NewDat27R {
        NewDat27R::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 28 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_28(&self) -> NewDat28R {
        NewDat28R::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_29(&self) -> NewDat29R {
        NewDat29R::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_30(&self) -> NewDat30R {
        NewDat30R::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    pub fn new_dat_31(&self) -> NewDat31R {
        NewDat31R::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_0(&mut self) -> NewDat0W<MsghandgrpMondbSpec> {
        NewDat0W::new(self, 0)
    }
    #[doc = "Bit 1 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_1(&mut self) -> NewDat1W<MsghandgrpMondbSpec> {
        NewDat1W::new(self, 1)
    }
    #[doc = "Bit 2 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_2(&mut self) -> NewDat2W<MsghandgrpMondbSpec> {
        NewDat2W::new(self, 2)
    }
    #[doc = "Bit 3 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_3(&mut self) -> NewDat3W<MsghandgrpMondbSpec> {
        NewDat3W::new(self, 3)
    }
    #[doc = "Bit 4 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_4(&mut self) -> NewDat4W<MsghandgrpMondbSpec> {
        NewDat4W::new(self, 4)
    }
    #[doc = "Bit 5 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_5(&mut self) -> NewDat5W<MsghandgrpMondbSpec> {
        NewDat5W::new(self, 5)
    }
    #[doc = "Bit 6 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_6(&mut self) -> NewDat6W<MsghandgrpMondbSpec> {
        NewDat6W::new(self, 6)
    }
    #[doc = "Bit 7 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_7(&mut self) -> NewDat7W<MsghandgrpMondbSpec> {
        NewDat7W::new(self, 7)
    }
    #[doc = "Bit 8 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_8(&mut self) -> NewDat8W<MsghandgrpMondbSpec> {
        NewDat8W::new(self, 8)
    }
    #[doc = "Bit 9 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_9(&mut self) -> NewDat9W<MsghandgrpMondbSpec> {
        NewDat9W::new(self, 9)
    }
    #[doc = "Bit 10 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_10(&mut self) -> NewDat10W<MsghandgrpMondbSpec> {
        NewDat10W::new(self, 10)
    }
    #[doc = "Bit 11 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_11(&mut self) -> NewDat11W<MsghandgrpMondbSpec> {
        NewDat11W::new(self, 11)
    }
    #[doc = "Bit 12 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_12(&mut self) -> NewDat12W<MsghandgrpMondbSpec> {
        NewDat12W::new(self, 12)
    }
    #[doc = "Bit 13 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_13(&mut self) -> NewDat13W<MsghandgrpMondbSpec> {
        NewDat13W::new(self, 13)
    }
    #[doc = "Bit 14 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_14(&mut self) -> NewDat14W<MsghandgrpMondbSpec> {
        NewDat14W::new(self, 14)
    }
    #[doc = "Bit 15 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_15(&mut self) -> NewDat15W<MsghandgrpMondbSpec> {
        NewDat15W::new(self, 15)
    }
    #[doc = "Bit 16 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_16(&mut self) -> NewDat16W<MsghandgrpMondbSpec> {
        NewDat16W::new(self, 16)
    }
    #[doc = "Bit 17 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_17(&mut self) -> NewDat17W<MsghandgrpMondbSpec> {
        NewDat17W::new(self, 17)
    }
    #[doc = "Bit 18 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_18(&mut self) -> NewDat18W<MsghandgrpMondbSpec> {
        NewDat18W::new(self, 18)
    }
    #[doc = "Bit 19 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_19(&mut self) -> NewDat19W<MsghandgrpMondbSpec> {
        NewDat19W::new(self, 19)
    }
    #[doc = "Bit 20 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_20(&mut self) -> NewDat20W<MsghandgrpMondbSpec> {
        NewDat20W::new(self, 20)
    }
    #[doc = "Bit 21 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_21(&mut self) -> NewDat21W<MsghandgrpMondbSpec> {
        NewDat21W::new(self, 21)
    }
    #[doc = "Bit 22 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_22(&mut self) -> NewDat22W<MsghandgrpMondbSpec> {
        NewDat22W::new(self, 22)
    }
    #[doc = "Bit 23 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_23(&mut self) -> NewDat23W<MsghandgrpMondbSpec> {
        NewDat23W::new(self, 23)
    }
    #[doc = "Bit 24 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_24(&mut self) -> NewDat24W<MsghandgrpMondbSpec> {
        NewDat24W::new(self, 24)
    }
    #[doc = "Bit 25 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_25(&mut self) -> NewDat25W<MsghandgrpMondbSpec> {
        NewDat25W::new(self, 25)
    }
    #[doc = "Bit 26 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_26(&mut self) -> NewDat26W<MsghandgrpMondbSpec> {
        NewDat26W::new(self, 26)
    }
    #[doc = "Bit 27 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_27(&mut self) -> NewDat27W<MsghandgrpMondbSpec> {
        NewDat27W::new(self, 27)
    }
    #[doc = "Bit 28 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_28(&mut self) -> NewDat28W<MsghandgrpMondbSpec> {
        NewDat28W::new(self, 28)
    }
    #[doc = "Bit 29 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_29(&mut self) -> NewDat29W<MsghandgrpMondbSpec> {
        NewDat29W::new(self, 29)
    }
    #[doc = "Bit 30 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_30(&mut self) -> NewDat30W<MsghandgrpMondbSpec> {
        NewDat30W::new(self, 30)
    }
    #[doc = "Bit 31 - New data bits for Message Objects 33 to 64. Array index i corresponds to Message Object i+33."]
    #[inline(always)]
    #[must_use]
    pub fn new_dat_31(&mut self) -> NewDat31W<MsghandgrpMondbSpec> {
        NewDat31W::new(self, 31)
    }
}
#[doc = "New data bits for Message Objects 33 to 64. By reading the NewDat bits, the CPU can check for which Message Object the data portion was updated. The NewDat bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Data Frame or reset by the Message Handler at start of a transmission.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_mondb::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MsghandgrpMondbSpec;
impl crate::RegisterSpec for MsghandgrpMondbSpec {
    type Ux = u32;
    const OFFSET: u64 = 160u64;
}
#[doc = "`read()` method returns [`msghandgrp_mondb::R`](R) reader structure"]
impl crate::Readable for MsghandgrpMondbSpec {}
#[doc = "`reset()` method sets msghandgrp_MONDB to value 0"]
impl crate::Resettable for MsghandgrpMondbSpec {
    const RESET_VALUE: u32 = 0;
}
