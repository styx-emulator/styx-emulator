// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `msghandgrp_MOTRD` reader"]
pub type R = crate::R<MsghandgrpMotrdSpec>;
#[doc = "Register `msghandgrp_MOTRD` writer"]
pub type W = crate::W<MsghandgrpMotrdSpec>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst0 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst0> for bool {
    #[inline(always)]
    fn from(variant: TxRqst0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_0` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst0R = crate::BitReader<TxRqst0>;
impl TxRqst0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst0 {
        match self.bits {
            false => TxRqst0::NotWaiting,
            true => TxRqst0::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst0::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst0::Pending
    }
}
#[doc = "Field `TxRqst_0` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst1 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst1> for bool {
    #[inline(always)]
    fn from(variant: TxRqst1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_1` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst1R = crate::BitReader<TxRqst1>;
impl TxRqst1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst1 {
        match self.bits {
            false => TxRqst1::NotWaiting,
            true => TxRqst1::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst1::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst1::Pending
    }
}
#[doc = "Field `TxRqst_1` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst2 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst2> for bool {
    #[inline(always)]
    fn from(variant: TxRqst2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_2` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst2R = crate::BitReader<TxRqst2>;
impl TxRqst2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst2 {
        match self.bits {
            false => TxRqst2::NotWaiting,
            true => TxRqst2::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst2::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst2::Pending
    }
}
#[doc = "Field `TxRqst_2` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst3 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst3> for bool {
    #[inline(always)]
    fn from(variant: TxRqst3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_3` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst3R = crate::BitReader<TxRqst3>;
impl TxRqst3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst3 {
        match self.bits {
            false => TxRqst3::NotWaiting,
            true => TxRqst3::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst3::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst3::Pending
    }
}
#[doc = "Field `TxRqst_3` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst4 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst4> for bool {
    #[inline(always)]
    fn from(variant: TxRqst4) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_4` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst4R = crate::BitReader<TxRqst4>;
impl TxRqst4R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst4 {
        match self.bits {
            false => TxRqst4::NotWaiting,
            true => TxRqst4::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst4::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst4::Pending
    }
}
#[doc = "Field `TxRqst_4` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst5 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst5> for bool {
    #[inline(always)]
    fn from(variant: TxRqst5) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_5` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst5R = crate::BitReader<TxRqst5>;
impl TxRqst5R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst5 {
        match self.bits {
            false => TxRqst5::NotWaiting,
            true => TxRqst5::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst5::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst5::Pending
    }
}
#[doc = "Field `TxRqst_5` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst6 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst6> for bool {
    #[inline(always)]
    fn from(variant: TxRqst6) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_6` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst6R = crate::BitReader<TxRqst6>;
impl TxRqst6R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst6 {
        match self.bits {
            false => TxRqst6::NotWaiting,
            true => TxRqst6::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst6::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst6::Pending
    }
}
#[doc = "Field `TxRqst_6` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst7 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst7> for bool {
    #[inline(always)]
    fn from(variant: TxRqst7) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_7` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst7R = crate::BitReader<TxRqst7>;
impl TxRqst7R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst7 {
        match self.bits {
            false => TxRqst7::NotWaiting,
            true => TxRqst7::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst7::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst7::Pending
    }
}
#[doc = "Field `TxRqst_7` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst7W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst8 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst8> for bool {
    #[inline(always)]
    fn from(variant: TxRqst8) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_8` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst8R = crate::BitReader<TxRqst8>;
impl TxRqst8R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst8 {
        match self.bits {
            false => TxRqst8::NotWaiting,
            true => TxRqst8::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst8::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst8::Pending
    }
}
#[doc = "Field `TxRqst_8` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst8W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst9 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst9> for bool {
    #[inline(always)]
    fn from(variant: TxRqst9) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_9` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst9R = crate::BitReader<TxRqst9>;
impl TxRqst9R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst9 {
        match self.bits {
            false => TxRqst9::NotWaiting,
            true => TxRqst9::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst9::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst9::Pending
    }
}
#[doc = "Field `TxRqst_9` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst9W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst10 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst10> for bool {
    #[inline(always)]
    fn from(variant: TxRqst10) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_10` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst10R = crate::BitReader<TxRqst10>;
impl TxRqst10R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst10 {
        match self.bits {
            false => TxRqst10::NotWaiting,
            true => TxRqst10::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst10::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst10::Pending
    }
}
#[doc = "Field `TxRqst_10` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst10W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst11 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst11> for bool {
    #[inline(always)]
    fn from(variant: TxRqst11) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_11` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst11R = crate::BitReader<TxRqst11>;
impl TxRqst11R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst11 {
        match self.bits {
            false => TxRqst11::NotWaiting,
            true => TxRqst11::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst11::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst11::Pending
    }
}
#[doc = "Field `TxRqst_11` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst11W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst12 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst12> for bool {
    #[inline(always)]
    fn from(variant: TxRqst12) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_12` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst12R = crate::BitReader<TxRqst12>;
impl TxRqst12R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst12 {
        match self.bits {
            false => TxRqst12::NotWaiting,
            true => TxRqst12::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst12::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst12::Pending
    }
}
#[doc = "Field `TxRqst_12` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst12W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst13 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst13> for bool {
    #[inline(always)]
    fn from(variant: TxRqst13) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_13` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst13R = crate::BitReader<TxRqst13>;
impl TxRqst13R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst13 {
        match self.bits {
            false => TxRqst13::NotWaiting,
            true => TxRqst13::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst13::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst13::Pending
    }
}
#[doc = "Field `TxRqst_13` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst13W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst14 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst14> for bool {
    #[inline(always)]
    fn from(variant: TxRqst14) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_14` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst14R = crate::BitReader<TxRqst14>;
impl TxRqst14R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst14 {
        match self.bits {
            false => TxRqst14::NotWaiting,
            true => TxRqst14::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst14::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst14::Pending
    }
}
#[doc = "Field `TxRqst_14` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst14W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst15 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst15> for bool {
    #[inline(always)]
    fn from(variant: TxRqst15) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_15` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst15R = crate::BitReader<TxRqst15>;
impl TxRqst15R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst15 {
        match self.bits {
            false => TxRqst15::NotWaiting,
            true => TxRqst15::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst15::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst15::Pending
    }
}
#[doc = "Field `TxRqst_15` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst15W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst16 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst16> for bool {
    #[inline(always)]
    fn from(variant: TxRqst16) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_16` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst16R = crate::BitReader<TxRqst16>;
impl TxRqst16R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst16 {
        match self.bits {
            false => TxRqst16::NotWaiting,
            true => TxRqst16::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst16::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst16::Pending
    }
}
#[doc = "Field `TxRqst_16` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst16W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst17 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst17> for bool {
    #[inline(always)]
    fn from(variant: TxRqst17) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_17` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst17R = crate::BitReader<TxRqst17>;
impl TxRqst17R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst17 {
        match self.bits {
            false => TxRqst17::NotWaiting,
            true => TxRqst17::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst17::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst17::Pending
    }
}
#[doc = "Field `TxRqst_17` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst17W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst18 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst18> for bool {
    #[inline(always)]
    fn from(variant: TxRqst18) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_18` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst18R = crate::BitReader<TxRqst18>;
impl TxRqst18R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst18 {
        match self.bits {
            false => TxRqst18::NotWaiting,
            true => TxRqst18::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst18::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst18::Pending
    }
}
#[doc = "Field `TxRqst_18` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst18W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst19 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst19> for bool {
    #[inline(always)]
    fn from(variant: TxRqst19) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_19` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst19R = crate::BitReader<TxRqst19>;
impl TxRqst19R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst19 {
        match self.bits {
            false => TxRqst19::NotWaiting,
            true => TxRqst19::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst19::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst19::Pending
    }
}
#[doc = "Field `TxRqst_19` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst19W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst20 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst20> for bool {
    #[inline(always)]
    fn from(variant: TxRqst20) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_20` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst20R = crate::BitReader<TxRqst20>;
impl TxRqst20R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst20 {
        match self.bits {
            false => TxRqst20::NotWaiting,
            true => TxRqst20::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst20::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst20::Pending
    }
}
#[doc = "Field `TxRqst_20` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst20W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst21 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst21> for bool {
    #[inline(always)]
    fn from(variant: TxRqst21) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_21` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst21R = crate::BitReader<TxRqst21>;
impl TxRqst21R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst21 {
        match self.bits {
            false => TxRqst21::NotWaiting,
            true => TxRqst21::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst21::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst21::Pending
    }
}
#[doc = "Field `TxRqst_21` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst21W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst22 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst22> for bool {
    #[inline(always)]
    fn from(variant: TxRqst22) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_22` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst22R = crate::BitReader<TxRqst22>;
impl TxRqst22R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst22 {
        match self.bits {
            false => TxRqst22::NotWaiting,
            true => TxRqst22::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst22::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst22::Pending
    }
}
#[doc = "Field `TxRqst_22` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst22W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst23 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst23> for bool {
    #[inline(always)]
    fn from(variant: TxRqst23) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_23` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst23R = crate::BitReader<TxRqst23>;
impl TxRqst23R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst23 {
        match self.bits {
            false => TxRqst23::NotWaiting,
            true => TxRqst23::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst23::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst23::Pending
    }
}
#[doc = "Field `TxRqst_23` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst23W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst24 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst24> for bool {
    #[inline(always)]
    fn from(variant: TxRqst24) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_24` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst24R = crate::BitReader<TxRqst24>;
impl TxRqst24R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst24 {
        match self.bits {
            false => TxRqst24::NotWaiting,
            true => TxRqst24::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst24::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst24::Pending
    }
}
#[doc = "Field `TxRqst_24` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst24W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst25 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst25> for bool {
    #[inline(always)]
    fn from(variant: TxRqst25) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_25` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst25R = crate::BitReader<TxRqst25>;
impl TxRqst25R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst25 {
        match self.bits {
            false => TxRqst25::NotWaiting,
            true => TxRqst25::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst25::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst25::Pending
    }
}
#[doc = "Field `TxRqst_25` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst25W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst26 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst26> for bool {
    #[inline(always)]
    fn from(variant: TxRqst26) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_26` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst26R = crate::BitReader<TxRqst26>;
impl TxRqst26R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst26 {
        match self.bits {
            false => TxRqst26::NotWaiting,
            true => TxRqst26::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst26::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst26::Pending
    }
}
#[doc = "Field `TxRqst_26` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst26W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst27 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst27> for bool {
    #[inline(always)]
    fn from(variant: TxRqst27) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_27` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst27R = crate::BitReader<TxRqst27>;
impl TxRqst27R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst27 {
        match self.bits {
            false => TxRqst27::NotWaiting,
            true => TxRqst27::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst27::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst27::Pending
    }
}
#[doc = "Field `TxRqst_27` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst27W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst28 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst28> for bool {
    #[inline(always)]
    fn from(variant: TxRqst28) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_28` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst28R = crate::BitReader<TxRqst28>;
impl TxRqst28R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst28 {
        match self.bits {
            false => TxRqst28::NotWaiting,
            true => TxRqst28::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst28::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst28::Pending
    }
}
#[doc = "Field `TxRqst_28` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst28W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst29 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst29> for bool {
    #[inline(always)]
    fn from(variant: TxRqst29) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_29` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst29R = crate::BitReader<TxRqst29>;
impl TxRqst29R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst29 {
        match self.bits {
            false => TxRqst29::NotWaiting,
            true => TxRqst29::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst29::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst29::Pending
    }
}
#[doc = "Field `TxRqst_29` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst29W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst30 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst30> for bool {
    #[inline(always)]
    fn from(variant: TxRqst30) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_30` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst30R = crate::BitReader<TxRqst30>;
impl TxRqst30R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst30 {
        match self.bits {
            false => TxRqst30::NotWaiting,
            true => TxRqst30::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst30::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst30::Pending
    }
}
#[doc = "Field `TxRqst_30` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst30W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRqst31 {
    #[doc = "0: `0`"]
    NotWaiting = 0,
    #[doc = "1: `1`"]
    Pending = 1,
}
impl From<TxRqst31> for bool {
    #[inline(always)]
    fn from(variant: TxRqst31) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `TxRqst_31` reader - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst31R = crate::BitReader<TxRqst31>;
impl TxRqst31R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TxRqst31 {
        match self.bits {
            false => TxRqst31::NotWaiting,
            true => TxRqst31::Pending,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_waiting(&self) -> bool {
        *self == TxRqst31::NotWaiting
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_pending(&self) -> bool {
        *self == TxRqst31::Pending
    }
}
#[doc = "Field `TxRqst_31` writer - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type TxRqst31W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_0(&self) -> TxRqst0R {
        TxRqst0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_1(&self) -> TxRqst1R {
        TxRqst1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_2(&self) -> TxRqst2R {
        TxRqst2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_3(&self) -> TxRqst3R {
        TxRqst3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_4(&self) -> TxRqst4R {
        TxRqst4R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_5(&self) -> TxRqst5R {
        TxRqst5R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_6(&self) -> TxRqst6R {
        TxRqst6R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_7(&self) -> TxRqst7R {
        TxRqst7R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_8(&self) -> TxRqst8R {
        TxRqst8R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_9(&self) -> TxRqst9R {
        TxRqst9R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_10(&self) -> TxRqst10R {
        TxRqst10R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_11(&self) -> TxRqst11R {
        TxRqst11R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_12(&self) -> TxRqst12R {
        TxRqst12R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_13(&self) -> TxRqst13R {
        TxRqst13R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_14(&self) -> TxRqst14R {
        TxRqst14R::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_15(&self) -> TxRqst15R {
        TxRqst15R::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_16(&self) -> TxRqst16R {
        TxRqst16R::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_17(&self) -> TxRqst17R {
        TxRqst17R::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_18(&self) -> TxRqst18R {
        TxRqst18R::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_19(&self) -> TxRqst19R {
        TxRqst19R::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_20(&self) -> TxRqst20R {
        TxRqst20R::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_21(&self) -> TxRqst21R {
        TxRqst21R::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_22(&self) -> TxRqst22R {
        TxRqst22R::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_23(&self) -> TxRqst23R {
        TxRqst23R::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_24(&self) -> TxRqst24R {
        TxRqst24R::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_25(&self) -> TxRqst25R {
        TxRqst25R::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_26(&self) -> TxRqst26R {
        TxRqst26R::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_27(&self) -> TxRqst27R {
        TxRqst27R::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 28 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_28(&self) -> TxRqst28R {
        TxRqst28R::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_29(&self) -> TxRqst29R {
        TxRqst29R::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_30(&self) -> TxRqst30R {
        TxRqst30R::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn tx_rqst_31(&self) -> TxRqst31R {
        TxRqst31R::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_0(&mut self) -> TxRqst0W<MsghandgrpMotrdSpec> {
        TxRqst0W::new(self, 0)
    }
    #[doc = "Bit 1 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_1(&mut self) -> TxRqst1W<MsghandgrpMotrdSpec> {
        TxRqst1W::new(self, 1)
    }
    #[doc = "Bit 2 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_2(&mut self) -> TxRqst2W<MsghandgrpMotrdSpec> {
        TxRqst2W::new(self, 2)
    }
    #[doc = "Bit 3 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_3(&mut self) -> TxRqst3W<MsghandgrpMotrdSpec> {
        TxRqst3W::new(self, 3)
    }
    #[doc = "Bit 4 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_4(&mut self) -> TxRqst4W<MsghandgrpMotrdSpec> {
        TxRqst4W::new(self, 4)
    }
    #[doc = "Bit 5 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_5(&mut self) -> TxRqst5W<MsghandgrpMotrdSpec> {
        TxRqst5W::new(self, 5)
    }
    #[doc = "Bit 6 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_6(&mut self) -> TxRqst6W<MsghandgrpMotrdSpec> {
        TxRqst6W::new(self, 6)
    }
    #[doc = "Bit 7 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_7(&mut self) -> TxRqst7W<MsghandgrpMotrdSpec> {
        TxRqst7W::new(self, 7)
    }
    #[doc = "Bit 8 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_8(&mut self) -> TxRqst8W<MsghandgrpMotrdSpec> {
        TxRqst8W::new(self, 8)
    }
    #[doc = "Bit 9 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_9(&mut self) -> TxRqst9W<MsghandgrpMotrdSpec> {
        TxRqst9W::new(self, 9)
    }
    #[doc = "Bit 10 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_10(&mut self) -> TxRqst10W<MsghandgrpMotrdSpec> {
        TxRqst10W::new(self, 10)
    }
    #[doc = "Bit 11 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_11(&mut self) -> TxRqst11W<MsghandgrpMotrdSpec> {
        TxRqst11W::new(self, 11)
    }
    #[doc = "Bit 12 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_12(&mut self) -> TxRqst12W<MsghandgrpMotrdSpec> {
        TxRqst12W::new(self, 12)
    }
    #[doc = "Bit 13 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_13(&mut self) -> TxRqst13W<MsghandgrpMotrdSpec> {
        TxRqst13W::new(self, 13)
    }
    #[doc = "Bit 14 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_14(&mut self) -> TxRqst14W<MsghandgrpMotrdSpec> {
        TxRqst14W::new(self, 14)
    }
    #[doc = "Bit 15 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_15(&mut self) -> TxRqst15W<MsghandgrpMotrdSpec> {
        TxRqst15W::new(self, 15)
    }
    #[doc = "Bit 16 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_16(&mut self) -> TxRqst16W<MsghandgrpMotrdSpec> {
        TxRqst16W::new(self, 16)
    }
    #[doc = "Bit 17 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_17(&mut self) -> TxRqst17W<MsghandgrpMotrdSpec> {
        TxRqst17W::new(self, 17)
    }
    #[doc = "Bit 18 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_18(&mut self) -> TxRqst18W<MsghandgrpMotrdSpec> {
        TxRqst18W::new(self, 18)
    }
    #[doc = "Bit 19 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_19(&mut self) -> TxRqst19W<MsghandgrpMotrdSpec> {
        TxRqst19W::new(self, 19)
    }
    #[doc = "Bit 20 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_20(&mut self) -> TxRqst20W<MsghandgrpMotrdSpec> {
        TxRqst20W::new(self, 20)
    }
    #[doc = "Bit 21 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_21(&mut self) -> TxRqst21W<MsghandgrpMotrdSpec> {
        TxRqst21W::new(self, 21)
    }
    #[doc = "Bit 22 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_22(&mut self) -> TxRqst22W<MsghandgrpMotrdSpec> {
        TxRqst22W::new(self, 22)
    }
    #[doc = "Bit 23 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_23(&mut self) -> TxRqst23W<MsghandgrpMotrdSpec> {
        TxRqst23W::new(self, 23)
    }
    #[doc = "Bit 24 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_24(&mut self) -> TxRqst24W<MsghandgrpMotrdSpec> {
        TxRqst24W::new(self, 24)
    }
    #[doc = "Bit 25 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_25(&mut self) -> TxRqst25W<MsghandgrpMotrdSpec> {
        TxRqst25W::new(self, 25)
    }
    #[doc = "Bit 26 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_26(&mut self) -> TxRqst26W<MsghandgrpMotrdSpec> {
        TxRqst26W::new(self, 26)
    }
    #[doc = "Bit 27 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_27(&mut self) -> TxRqst27W<MsghandgrpMotrdSpec> {
        TxRqst27W::new(self, 27)
    }
    #[doc = "Bit 28 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_28(&mut self) -> TxRqst28W<MsghandgrpMotrdSpec> {
        TxRqst28W::new(self, 28)
    }
    #[doc = "Bit 29 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_29(&mut self) -> TxRqst29W<MsghandgrpMotrdSpec> {
        TxRqst29W::new(self, 29)
    }
    #[doc = "Bit 30 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_30(&mut self) -> TxRqst30W<MsghandgrpMotrdSpec> {
        TxRqst30W::new(self, 30)
    }
    #[doc = "Bit 31 - Transmission request bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn tx_rqst_31(&mut self) -> TxRqst31W<MsghandgrpMotrdSpec> {
        TxRqst31W::new(self, 31)
    }
}
#[doc = "Transmission request bits for Message Objects 97 to 128. By reading the TxRqst bits, the CPU can check for which Message Object a Transmission Request is pending. The TxRqst bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception of a Remote Frame or reset by the Message Handler after a successful transmission.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_motrd::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MsghandgrpMotrdSpec;
impl crate::RegisterSpec for MsghandgrpMotrdSpec {
    type Ux = u32;
    const OFFSET: u64 = 148u64;
}
#[doc = "`read()` method returns [`msghandgrp_motrd::R`](R) reader structure"]
impl crate::Readable for MsghandgrpMotrdSpec {}
#[doc = "`reset()` method sets msghandgrp_MOTRD to value 0"]
impl crate::Resettable for MsghandgrpMotrdSpec {
    const RESET_VALUE: u32 = 0;
}
