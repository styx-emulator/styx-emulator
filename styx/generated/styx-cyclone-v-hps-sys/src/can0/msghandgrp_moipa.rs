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
#[doc = "Register `msghandgrp_MOIPA` reader"]
pub type R = crate::R<MsghandgrpMoipaSpec>;
#[doc = "Register `msghandgrp_MOIPA` writer"]
pub type W = crate::W<MsghandgrpMoipaSpec>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd0 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd0> for bool {
    #[inline(always)]
    fn from(variant: IntPnd0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_0` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd0R = crate::BitReader<IntPnd0>;
impl IntPnd0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd0 {
        match self.bits {
            false => IntPnd0::NotSrc,
            true => IntPnd0::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd0::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd0::Src
    }
}
#[doc = "Field `IntPnd_0` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd1 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd1> for bool {
    #[inline(always)]
    fn from(variant: IntPnd1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_1` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd1R = crate::BitReader<IntPnd1>;
impl IntPnd1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd1 {
        match self.bits {
            false => IntPnd1::NotSrc,
            true => IntPnd1::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd1::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd1::Src
    }
}
#[doc = "Field `IntPnd_1` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd2 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd2> for bool {
    #[inline(always)]
    fn from(variant: IntPnd2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_2` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd2R = crate::BitReader<IntPnd2>;
impl IntPnd2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd2 {
        match self.bits {
            false => IntPnd2::NotSrc,
            true => IntPnd2::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd2::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd2::Src
    }
}
#[doc = "Field `IntPnd_2` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd3 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd3> for bool {
    #[inline(always)]
    fn from(variant: IntPnd3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_3` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd3R = crate::BitReader<IntPnd3>;
impl IntPnd3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd3 {
        match self.bits {
            false => IntPnd3::NotSrc,
            true => IntPnd3::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd3::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd3::Src
    }
}
#[doc = "Field `IntPnd_3` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd4 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd4> for bool {
    #[inline(always)]
    fn from(variant: IntPnd4) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_4` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd4R = crate::BitReader<IntPnd4>;
impl IntPnd4R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd4 {
        match self.bits {
            false => IntPnd4::NotSrc,
            true => IntPnd4::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd4::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd4::Src
    }
}
#[doc = "Field `IntPnd_4` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd5 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd5> for bool {
    #[inline(always)]
    fn from(variant: IntPnd5) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_5` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd5R = crate::BitReader<IntPnd5>;
impl IntPnd5R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd5 {
        match self.bits {
            false => IntPnd5::NotSrc,
            true => IntPnd5::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd5::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd5::Src
    }
}
#[doc = "Field `IntPnd_5` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd6 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd6> for bool {
    #[inline(always)]
    fn from(variant: IntPnd6) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_6` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd6R = crate::BitReader<IntPnd6>;
impl IntPnd6R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd6 {
        match self.bits {
            false => IntPnd6::NotSrc,
            true => IntPnd6::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd6::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd6::Src
    }
}
#[doc = "Field `IntPnd_6` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd7 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd7> for bool {
    #[inline(always)]
    fn from(variant: IntPnd7) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_7` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd7R = crate::BitReader<IntPnd7>;
impl IntPnd7R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd7 {
        match self.bits {
            false => IntPnd7::NotSrc,
            true => IntPnd7::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd7::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd7::Src
    }
}
#[doc = "Field `IntPnd_7` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd7W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd8 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd8> for bool {
    #[inline(always)]
    fn from(variant: IntPnd8) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_8` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd8R = crate::BitReader<IntPnd8>;
impl IntPnd8R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd8 {
        match self.bits {
            false => IntPnd8::NotSrc,
            true => IntPnd8::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd8::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd8::Src
    }
}
#[doc = "Field `IntPnd_8` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd8W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd9 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd9> for bool {
    #[inline(always)]
    fn from(variant: IntPnd9) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_9` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd9R = crate::BitReader<IntPnd9>;
impl IntPnd9R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd9 {
        match self.bits {
            false => IntPnd9::NotSrc,
            true => IntPnd9::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd9::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd9::Src
    }
}
#[doc = "Field `IntPnd_9` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd9W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd10 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd10> for bool {
    #[inline(always)]
    fn from(variant: IntPnd10) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_10` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd10R = crate::BitReader<IntPnd10>;
impl IntPnd10R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd10 {
        match self.bits {
            false => IntPnd10::NotSrc,
            true => IntPnd10::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd10::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd10::Src
    }
}
#[doc = "Field `IntPnd_10` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd10W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd11 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd11> for bool {
    #[inline(always)]
    fn from(variant: IntPnd11) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_11` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd11R = crate::BitReader<IntPnd11>;
impl IntPnd11R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd11 {
        match self.bits {
            false => IntPnd11::NotSrc,
            true => IntPnd11::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd11::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd11::Src
    }
}
#[doc = "Field `IntPnd_11` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd11W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd12 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd12> for bool {
    #[inline(always)]
    fn from(variant: IntPnd12) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_12` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd12R = crate::BitReader<IntPnd12>;
impl IntPnd12R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd12 {
        match self.bits {
            false => IntPnd12::NotSrc,
            true => IntPnd12::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd12::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd12::Src
    }
}
#[doc = "Field `IntPnd_12` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd12W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd13 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd13> for bool {
    #[inline(always)]
    fn from(variant: IntPnd13) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_13` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd13R = crate::BitReader<IntPnd13>;
impl IntPnd13R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd13 {
        match self.bits {
            false => IntPnd13::NotSrc,
            true => IntPnd13::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd13::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd13::Src
    }
}
#[doc = "Field `IntPnd_13` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd13W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd14 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd14> for bool {
    #[inline(always)]
    fn from(variant: IntPnd14) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_14` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd14R = crate::BitReader<IntPnd14>;
impl IntPnd14R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd14 {
        match self.bits {
            false => IntPnd14::NotSrc,
            true => IntPnd14::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd14::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd14::Src
    }
}
#[doc = "Field `IntPnd_14` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd14W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd15 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd15> for bool {
    #[inline(always)]
    fn from(variant: IntPnd15) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_15` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd15R = crate::BitReader<IntPnd15>;
impl IntPnd15R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd15 {
        match self.bits {
            false => IntPnd15::NotSrc,
            true => IntPnd15::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd15::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd15::Src
    }
}
#[doc = "Field `IntPnd_15` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd15W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd16 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd16> for bool {
    #[inline(always)]
    fn from(variant: IntPnd16) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_16` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd16R = crate::BitReader<IntPnd16>;
impl IntPnd16R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd16 {
        match self.bits {
            false => IntPnd16::NotSrc,
            true => IntPnd16::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd16::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd16::Src
    }
}
#[doc = "Field `IntPnd_16` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd16W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd17 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd17> for bool {
    #[inline(always)]
    fn from(variant: IntPnd17) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_17` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd17R = crate::BitReader<IntPnd17>;
impl IntPnd17R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd17 {
        match self.bits {
            false => IntPnd17::NotSrc,
            true => IntPnd17::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd17::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd17::Src
    }
}
#[doc = "Field `IntPnd_17` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd17W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd18 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd18> for bool {
    #[inline(always)]
    fn from(variant: IntPnd18) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_18` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd18R = crate::BitReader<IntPnd18>;
impl IntPnd18R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd18 {
        match self.bits {
            false => IntPnd18::NotSrc,
            true => IntPnd18::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd18::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd18::Src
    }
}
#[doc = "Field `IntPnd_18` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd18W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd19 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd19> for bool {
    #[inline(always)]
    fn from(variant: IntPnd19) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_19` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd19R = crate::BitReader<IntPnd19>;
impl IntPnd19R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd19 {
        match self.bits {
            false => IntPnd19::NotSrc,
            true => IntPnd19::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd19::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd19::Src
    }
}
#[doc = "Field `IntPnd_19` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd19W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd20 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd20> for bool {
    #[inline(always)]
    fn from(variant: IntPnd20) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_20` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd20R = crate::BitReader<IntPnd20>;
impl IntPnd20R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd20 {
        match self.bits {
            false => IntPnd20::NotSrc,
            true => IntPnd20::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd20::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd20::Src
    }
}
#[doc = "Field `IntPnd_20` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd20W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd21 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd21> for bool {
    #[inline(always)]
    fn from(variant: IntPnd21) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_21` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd21R = crate::BitReader<IntPnd21>;
impl IntPnd21R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd21 {
        match self.bits {
            false => IntPnd21::NotSrc,
            true => IntPnd21::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd21::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd21::Src
    }
}
#[doc = "Field `IntPnd_21` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd21W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd22 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd22> for bool {
    #[inline(always)]
    fn from(variant: IntPnd22) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_22` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd22R = crate::BitReader<IntPnd22>;
impl IntPnd22R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd22 {
        match self.bits {
            false => IntPnd22::NotSrc,
            true => IntPnd22::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd22::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd22::Src
    }
}
#[doc = "Field `IntPnd_22` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd22W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd23 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd23> for bool {
    #[inline(always)]
    fn from(variant: IntPnd23) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_23` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd23R = crate::BitReader<IntPnd23>;
impl IntPnd23R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd23 {
        match self.bits {
            false => IntPnd23::NotSrc,
            true => IntPnd23::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd23::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd23::Src
    }
}
#[doc = "Field `IntPnd_23` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd23W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd24 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd24> for bool {
    #[inline(always)]
    fn from(variant: IntPnd24) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_24` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd24R = crate::BitReader<IntPnd24>;
impl IntPnd24R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd24 {
        match self.bits {
            false => IntPnd24::NotSrc,
            true => IntPnd24::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd24::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd24::Src
    }
}
#[doc = "Field `IntPnd_24` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd24W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd25 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd25> for bool {
    #[inline(always)]
    fn from(variant: IntPnd25) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_25` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd25R = crate::BitReader<IntPnd25>;
impl IntPnd25R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd25 {
        match self.bits {
            false => IntPnd25::NotSrc,
            true => IntPnd25::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd25::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd25::Src
    }
}
#[doc = "Field `IntPnd_25` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd25W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd26 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd26> for bool {
    #[inline(always)]
    fn from(variant: IntPnd26) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_26` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd26R = crate::BitReader<IntPnd26>;
impl IntPnd26R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd26 {
        match self.bits {
            false => IntPnd26::NotSrc,
            true => IntPnd26::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd26::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd26::Src
    }
}
#[doc = "Field `IntPnd_26` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd26W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd27 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd27> for bool {
    #[inline(always)]
    fn from(variant: IntPnd27) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_27` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd27R = crate::BitReader<IntPnd27>;
impl IntPnd27R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd27 {
        match self.bits {
            false => IntPnd27::NotSrc,
            true => IntPnd27::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd27::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd27::Src
    }
}
#[doc = "Field `IntPnd_27` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd27W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd28 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd28> for bool {
    #[inline(always)]
    fn from(variant: IntPnd28) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_28` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd28R = crate::BitReader<IntPnd28>;
impl IntPnd28R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd28 {
        match self.bits {
            false => IntPnd28::NotSrc,
            true => IntPnd28::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd28::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd28::Src
    }
}
#[doc = "Field `IntPnd_28` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd28W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd29 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd29> for bool {
    #[inline(always)]
    fn from(variant: IntPnd29) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_29` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd29R = crate::BitReader<IntPnd29>;
impl IntPnd29R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd29 {
        match self.bits {
            false => IntPnd29::NotSrc,
            true => IntPnd29::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd29::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd29::Src
    }
}
#[doc = "Field `IntPnd_29` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd29W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd30 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd30> for bool {
    #[inline(always)]
    fn from(variant: IntPnd30) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_30` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd30R = crate::BitReader<IntPnd30>;
impl IntPnd30R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd30 {
        match self.bits {
            false => IntPnd30::NotSrc,
            true => IntPnd30::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd30::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd30::Src
    }
}
#[doc = "Field `IntPnd_30` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd30W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPnd31 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPnd31> for bool {
    #[inline(always)]
    fn from(variant: IntPnd31) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPnd_31` reader - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd31R = crate::BitReader<IntPnd31>;
impl IntPnd31R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPnd31 {
        match self.bits {
            false => IntPnd31::NotSrc,
            true => IntPnd31::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPnd31::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPnd31::Src
    }
}
#[doc = "Field `IntPnd_31` writer - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
pub type IntPnd31W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_0(&self) -> IntPnd0R {
        IntPnd0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_1(&self) -> IntPnd1R {
        IntPnd1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_2(&self) -> IntPnd2R {
        IntPnd2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_3(&self) -> IntPnd3R {
        IntPnd3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_4(&self) -> IntPnd4R {
        IntPnd4R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_5(&self) -> IntPnd5R {
        IntPnd5R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_6(&self) -> IntPnd6R {
        IntPnd6R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_7(&self) -> IntPnd7R {
        IntPnd7R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_8(&self) -> IntPnd8R {
        IntPnd8R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_9(&self) -> IntPnd9R {
        IntPnd9R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_10(&self) -> IntPnd10R {
        IntPnd10R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_11(&self) -> IntPnd11R {
        IntPnd11R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_12(&self) -> IntPnd12R {
        IntPnd12R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_13(&self) -> IntPnd13R {
        IntPnd13R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_14(&self) -> IntPnd14R {
        IntPnd14R::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_15(&self) -> IntPnd15R {
        IntPnd15R::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_16(&self) -> IntPnd16R {
        IntPnd16R::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_17(&self) -> IntPnd17R {
        IntPnd17R::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_18(&self) -> IntPnd18R {
        IntPnd18R::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_19(&self) -> IntPnd19R {
        IntPnd19R::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_20(&self) -> IntPnd20R {
        IntPnd20R::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_21(&self) -> IntPnd21R {
        IntPnd21R::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_22(&self) -> IntPnd22R {
        IntPnd22R::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_23(&self) -> IntPnd23R {
        IntPnd23R::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_24(&self) -> IntPnd24R {
        IntPnd24R::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_25(&self) -> IntPnd25R {
        IntPnd25R::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_26(&self) -> IntPnd26R {
        IntPnd26R::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_27(&self) -> IntPnd27R {
        IntPnd27R::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 28 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_28(&self) -> IntPnd28R {
        IntPnd28R::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_29(&self) -> IntPnd29R {
        IntPnd29R::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_30(&self) -> IntPnd30R {
        IntPnd30R::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    pub fn int_pnd_31(&self) -> IntPnd31R {
        IntPnd31R::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_0(&mut self) -> IntPnd0W<MsghandgrpMoipaSpec> {
        IntPnd0W::new(self, 0)
    }
    #[doc = "Bit 1 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_1(&mut self) -> IntPnd1W<MsghandgrpMoipaSpec> {
        IntPnd1W::new(self, 1)
    }
    #[doc = "Bit 2 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_2(&mut self) -> IntPnd2W<MsghandgrpMoipaSpec> {
        IntPnd2W::new(self, 2)
    }
    #[doc = "Bit 3 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_3(&mut self) -> IntPnd3W<MsghandgrpMoipaSpec> {
        IntPnd3W::new(self, 3)
    }
    #[doc = "Bit 4 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_4(&mut self) -> IntPnd4W<MsghandgrpMoipaSpec> {
        IntPnd4W::new(self, 4)
    }
    #[doc = "Bit 5 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_5(&mut self) -> IntPnd5W<MsghandgrpMoipaSpec> {
        IntPnd5W::new(self, 5)
    }
    #[doc = "Bit 6 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_6(&mut self) -> IntPnd6W<MsghandgrpMoipaSpec> {
        IntPnd6W::new(self, 6)
    }
    #[doc = "Bit 7 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_7(&mut self) -> IntPnd7W<MsghandgrpMoipaSpec> {
        IntPnd7W::new(self, 7)
    }
    #[doc = "Bit 8 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_8(&mut self) -> IntPnd8W<MsghandgrpMoipaSpec> {
        IntPnd8W::new(self, 8)
    }
    #[doc = "Bit 9 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_9(&mut self) -> IntPnd9W<MsghandgrpMoipaSpec> {
        IntPnd9W::new(self, 9)
    }
    #[doc = "Bit 10 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_10(&mut self) -> IntPnd10W<MsghandgrpMoipaSpec> {
        IntPnd10W::new(self, 10)
    }
    #[doc = "Bit 11 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_11(&mut self) -> IntPnd11W<MsghandgrpMoipaSpec> {
        IntPnd11W::new(self, 11)
    }
    #[doc = "Bit 12 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_12(&mut self) -> IntPnd12W<MsghandgrpMoipaSpec> {
        IntPnd12W::new(self, 12)
    }
    #[doc = "Bit 13 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_13(&mut self) -> IntPnd13W<MsghandgrpMoipaSpec> {
        IntPnd13W::new(self, 13)
    }
    #[doc = "Bit 14 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_14(&mut self) -> IntPnd14W<MsghandgrpMoipaSpec> {
        IntPnd14W::new(self, 14)
    }
    #[doc = "Bit 15 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_15(&mut self) -> IntPnd15W<MsghandgrpMoipaSpec> {
        IntPnd15W::new(self, 15)
    }
    #[doc = "Bit 16 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_16(&mut self) -> IntPnd16W<MsghandgrpMoipaSpec> {
        IntPnd16W::new(self, 16)
    }
    #[doc = "Bit 17 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_17(&mut self) -> IntPnd17W<MsghandgrpMoipaSpec> {
        IntPnd17W::new(self, 17)
    }
    #[doc = "Bit 18 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_18(&mut self) -> IntPnd18W<MsghandgrpMoipaSpec> {
        IntPnd18W::new(self, 18)
    }
    #[doc = "Bit 19 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_19(&mut self) -> IntPnd19W<MsghandgrpMoipaSpec> {
        IntPnd19W::new(self, 19)
    }
    #[doc = "Bit 20 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_20(&mut self) -> IntPnd20W<MsghandgrpMoipaSpec> {
        IntPnd20W::new(self, 20)
    }
    #[doc = "Bit 21 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_21(&mut self) -> IntPnd21W<MsghandgrpMoipaSpec> {
        IntPnd21W::new(self, 21)
    }
    #[doc = "Bit 22 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_22(&mut self) -> IntPnd22W<MsghandgrpMoipaSpec> {
        IntPnd22W::new(self, 22)
    }
    #[doc = "Bit 23 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_23(&mut self) -> IntPnd23W<MsghandgrpMoipaSpec> {
        IntPnd23W::new(self, 23)
    }
    #[doc = "Bit 24 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_24(&mut self) -> IntPnd24W<MsghandgrpMoipaSpec> {
        IntPnd24W::new(self, 24)
    }
    #[doc = "Bit 25 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_25(&mut self) -> IntPnd25W<MsghandgrpMoipaSpec> {
        IntPnd25W::new(self, 25)
    }
    #[doc = "Bit 26 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_26(&mut self) -> IntPnd26W<MsghandgrpMoipaSpec> {
        IntPnd26W::new(self, 26)
    }
    #[doc = "Bit 27 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_27(&mut self) -> IntPnd27W<MsghandgrpMoipaSpec> {
        IntPnd27W::new(self, 27)
    }
    #[doc = "Bit 28 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_28(&mut self) -> IntPnd28W<MsghandgrpMoipaSpec> {
        IntPnd28W::new(self, 28)
    }
    #[doc = "Bit 29 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_29(&mut self) -> IntPnd29W<MsghandgrpMoipaSpec> {
        IntPnd29W::new(self, 29)
    }
    #[doc = "Bit 30 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_30(&mut self) -> IntPnd30W<MsghandgrpMoipaSpec> {
        IntPnd30W::new(self, 30)
    }
    #[doc = "Bit 31 - Interrupt pending bits for Message Objects 1 to 32. Array index i corresponds to Message Object i+1."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_31(&mut self) -> IntPnd31W<MsghandgrpMoipaSpec> {
        IntPnd31W::new(self, 31)
    }
}
#[doc = "Interrupt pending bits for Message Objects 1 to 32. By reading the IntPnd bits, the CPU can check for which Message Object an interrupt is pending. The IntPnd bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers or set by the Message Handler after reception or after a successful transmission of a frame. This will also affect the valid of IntID in the Interrupt Register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_moipa::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MsghandgrpMoipaSpec;
impl crate::RegisterSpec for MsghandgrpMoipaSpec {
    type Ux = u32;
    const OFFSET: u64 = 176u64;
}
#[doc = "`read()` method returns [`msghandgrp_moipa::R`](R) reader structure"]
impl crate::Readable for MsghandgrpMoipaSpec {}
#[doc = "`reset()` method sets msghandgrp_MOIPA to value 0"]
impl crate::Resettable for MsghandgrpMoipaSpec {
    const RESET_VALUE: u32 = 0;
}
