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
#[doc = "Register `msghandgrp_MOVALD` reader"]
pub type R = crate::R<MsghandgrpMovaldSpec>;
#[doc = "Register `msghandgrp_MOVALD` writer"]
pub type W = crate::W<MsghandgrpMovaldSpec>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal0 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal0> for bool {
    #[inline(always)]
    fn from(variant: MsgVal0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_0` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal0R = crate::BitReader<MsgVal0>;
impl MsgVal0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal0 {
        match self.bits {
            false => MsgVal0::Ignored,
            true => MsgVal0::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal0::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal0::Considered
    }
}
#[doc = "Field `MsgVal_0` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal1 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal1> for bool {
    #[inline(always)]
    fn from(variant: MsgVal1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_1` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal1R = crate::BitReader<MsgVal1>;
impl MsgVal1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal1 {
        match self.bits {
            false => MsgVal1::Ignored,
            true => MsgVal1::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal1::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal1::Considered
    }
}
#[doc = "Field `MsgVal_1` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal2 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal2> for bool {
    #[inline(always)]
    fn from(variant: MsgVal2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_2` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal2R = crate::BitReader<MsgVal2>;
impl MsgVal2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal2 {
        match self.bits {
            false => MsgVal2::Ignored,
            true => MsgVal2::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal2::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal2::Considered
    }
}
#[doc = "Field `MsgVal_2` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal3 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal3> for bool {
    #[inline(always)]
    fn from(variant: MsgVal3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_3` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal3R = crate::BitReader<MsgVal3>;
impl MsgVal3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal3 {
        match self.bits {
            false => MsgVal3::Ignored,
            true => MsgVal3::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal3::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal3::Considered
    }
}
#[doc = "Field `MsgVal_3` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal4 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal4> for bool {
    #[inline(always)]
    fn from(variant: MsgVal4) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_4` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal4R = crate::BitReader<MsgVal4>;
impl MsgVal4R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal4 {
        match self.bits {
            false => MsgVal4::Ignored,
            true => MsgVal4::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal4::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal4::Considered
    }
}
#[doc = "Field `MsgVal_4` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal5 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal5> for bool {
    #[inline(always)]
    fn from(variant: MsgVal5) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_5` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal5R = crate::BitReader<MsgVal5>;
impl MsgVal5R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal5 {
        match self.bits {
            false => MsgVal5::Ignored,
            true => MsgVal5::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal5::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal5::Considered
    }
}
#[doc = "Field `MsgVal_5` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal6 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal6> for bool {
    #[inline(always)]
    fn from(variant: MsgVal6) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_6` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal6R = crate::BitReader<MsgVal6>;
impl MsgVal6R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal6 {
        match self.bits {
            false => MsgVal6::Ignored,
            true => MsgVal6::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal6::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal6::Considered
    }
}
#[doc = "Field `MsgVal_6` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal7 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal7> for bool {
    #[inline(always)]
    fn from(variant: MsgVal7) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_7` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal7R = crate::BitReader<MsgVal7>;
impl MsgVal7R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal7 {
        match self.bits {
            false => MsgVal7::Ignored,
            true => MsgVal7::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal7::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal7::Considered
    }
}
#[doc = "Field `MsgVal_7` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal7W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal8 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal8> for bool {
    #[inline(always)]
    fn from(variant: MsgVal8) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_8` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal8R = crate::BitReader<MsgVal8>;
impl MsgVal8R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal8 {
        match self.bits {
            false => MsgVal8::Ignored,
            true => MsgVal8::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal8::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal8::Considered
    }
}
#[doc = "Field `MsgVal_8` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal8W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal9 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal9> for bool {
    #[inline(always)]
    fn from(variant: MsgVal9) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_9` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal9R = crate::BitReader<MsgVal9>;
impl MsgVal9R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal9 {
        match self.bits {
            false => MsgVal9::Ignored,
            true => MsgVal9::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal9::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal9::Considered
    }
}
#[doc = "Field `MsgVal_9` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal9W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal10 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal10> for bool {
    #[inline(always)]
    fn from(variant: MsgVal10) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_10` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal10R = crate::BitReader<MsgVal10>;
impl MsgVal10R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal10 {
        match self.bits {
            false => MsgVal10::Ignored,
            true => MsgVal10::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal10::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal10::Considered
    }
}
#[doc = "Field `MsgVal_10` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal10W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal11 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal11> for bool {
    #[inline(always)]
    fn from(variant: MsgVal11) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_11` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal11R = crate::BitReader<MsgVal11>;
impl MsgVal11R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal11 {
        match self.bits {
            false => MsgVal11::Ignored,
            true => MsgVal11::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal11::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal11::Considered
    }
}
#[doc = "Field `MsgVal_11` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal11W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal12 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal12> for bool {
    #[inline(always)]
    fn from(variant: MsgVal12) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_12` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal12R = crate::BitReader<MsgVal12>;
impl MsgVal12R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal12 {
        match self.bits {
            false => MsgVal12::Ignored,
            true => MsgVal12::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal12::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal12::Considered
    }
}
#[doc = "Field `MsgVal_12` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal12W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal13 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal13> for bool {
    #[inline(always)]
    fn from(variant: MsgVal13) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_13` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal13R = crate::BitReader<MsgVal13>;
impl MsgVal13R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal13 {
        match self.bits {
            false => MsgVal13::Ignored,
            true => MsgVal13::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal13::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal13::Considered
    }
}
#[doc = "Field `MsgVal_13` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal13W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal14 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal14> for bool {
    #[inline(always)]
    fn from(variant: MsgVal14) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_14` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal14R = crate::BitReader<MsgVal14>;
impl MsgVal14R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal14 {
        match self.bits {
            false => MsgVal14::Ignored,
            true => MsgVal14::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal14::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal14::Considered
    }
}
#[doc = "Field `MsgVal_14` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal14W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal15 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal15> for bool {
    #[inline(always)]
    fn from(variant: MsgVal15) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_15` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal15R = crate::BitReader<MsgVal15>;
impl MsgVal15R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal15 {
        match self.bits {
            false => MsgVal15::Ignored,
            true => MsgVal15::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal15::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal15::Considered
    }
}
#[doc = "Field `MsgVal_15` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal15W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal16 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal16> for bool {
    #[inline(always)]
    fn from(variant: MsgVal16) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_16` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal16R = crate::BitReader<MsgVal16>;
impl MsgVal16R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal16 {
        match self.bits {
            false => MsgVal16::Ignored,
            true => MsgVal16::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal16::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal16::Considered
    }
}
#[doc = "Field `MsgVal_16` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal16W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal17 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal17> for bool {
    #[inline(always)]
    fn from(variant: MsgVal17) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_17` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal17R = crate::BitReader<MsgVal17>;
impl MsgVal17R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal17 {
        match self.bits {
            false => MsgVal17::Ignored,
            true => MsgVal17::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal17::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal17::Considered
    }
}
#[doc = "Field `MsgVal_17` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal17W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal18 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal18> for bool {
    #[inline(always)]
    fn from(variant: MsgVal18) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_18` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal18R = crate::BitReader<MsgVal18>;
impl MsgVal18R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal18 {
        match self.bits {
            false => MsgVal18::Ignored,
            true => MsgVal18::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal18::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal18::Considered
    }
}
#[doc = "Field `MsgVal_18` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal18W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal19 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal19> for bool {
    #[inline(always)]
    fn from(variant: MsgVal19) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_19` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal19R = crate::BitReader<MsgVal19>;
impl MsgVal19R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal19 {
        match self.bits {
            false => MsgVal19::Ignored,
            true => MsgVal19::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal19::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal19::Considered
    }
}
#[doc = "Field `MsgVal_19` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal19W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal20 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal20> for bool {
    #[inline(always)]
    fn from(variant: MsgVal20) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_20` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal20R = crate::BitReader<MsgVal20>;
impl MsgVal20R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal20 {
        match self.bits {
            false => MsgVal20::Ignored,
            true => MsgVal20::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal20::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal20::Considered
    }
}
#[doc = "Field `MsgVal_20` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal20W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal21 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal21> for bool {
    #[inline(always)]
    fn from(variant: MsgVal21) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_21` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal21R = crate::BitReader<MsgVal21>;
impl MsgVal21R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal21 {
        match self.bits {
            false => MsgVal21::Ignored,
            true => MsgVal21::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal21::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal21::Considered
    }
}
#[doc = "Field `MsgVal_21` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal21W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal22 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal22> for bool {
    #[inline(always)]
    fn from(variant: MsgVal22) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_22` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal22R = crate::BitReader<MsgVal22>;
impl MsgVal22R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal22 {
        match self.bits {
            false => MsgVal22::Ignored,
            true => MsgVal22::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal22::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal22::Considered
    }
}
#[doc = "Field `MsgVal_22` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal22W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal23 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal23> for bool {
    #[inline(always)]
    fn from(variant: MsgVal23) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_23` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal23R = crate::BitReader<MsgVal23>;
impl MsgVal23R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal23 {
        match self.bits {
            false => MsgVal23::Ignored,
            true => MsgVal23::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal23::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal23::Considered
    }
}
#[doc = "Field `MsgVal_23` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal23W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal24 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal24> for bool {
    #[inline(always)]
    fn from(variant: MsgVal24) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_24` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal24R = crate::BitReader<MsgVal24>;
impl MsgVal24R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal24 {
        match self.bits {
            false => MsgVal24::Ignored,
            true => MsgVal24::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal24::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal24::Considered
    }
}
#[doc = "Field `MsgVal_24` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal24W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal25 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal25> for bool {
    #[inline(always)]
    fn from(variant: MsgVal25) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_25` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal25R = crate::BitReader<MsgVal25>;
impl MsgVal25R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal25 {
        match self.bits {
            false => MsgVal25::Ignored,
            true => MsgVal25::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal25::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal25::Considered
    }
}
#[doc = "Field `MsgVal_25` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal25W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal26 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal26> for bool {
    #[inline(always)]
    fn from(variant: MsgVal26) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_26` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal26R = crate::BitReader<MsgVal26>;
impl MsgVal26R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal26 {
        match self.bits {
            false => MsgVal26::Ignored,
            true => MsgVal26::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal26::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal26::Considered
    }
}
#[doc = "Field `MsgVal_26` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal26W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal27 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal27> for bool {
    #[inline(always)]
    fn from(variant: MsgVal27) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_27` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal27R = crate::BitReader<MsgVal27>;
impl MsgVal27R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal27 {
        match self.bits {
            false => MsgVal27::Ignored,
            true => MsgVal27::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal27::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal27::Considered
    }
}
#[doc = "Field `MsgVal_27` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal27W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal28 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal28> for bool {
    #[inline(always)]
    fn from(variant: MsgVal28) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_28` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal28R = crate::BitReader<MsgVal28>;
impl MsgVal28R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal28 {
        match self.bits {
            false => MsgVal28::Ignored,
            true => MsgVal28::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal28::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal28::Considered
    }
}
#[doc = "Field `MsgVal_28` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal28W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal29 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal29> for bool {
    #[inline(always)]
    fn from(variant: MsgVal29) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_29` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal29R = crate::BitReader<MsgVal29>;
impl MsgVal29R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal29 {
        match self.bits {
            false => MsgVal29::Ignored,
            true => MsgVal29::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal29::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal29::Considered
    }
}
#[doc = "Field `MsgVal_29` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal29W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal30 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal30> for bool {
    #[inline(always)]
    fn from(variant: MsgVal30) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_30` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal30R = crate::BitReader<MsgVal30>;
impl MsgVal30R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal30 {
        match self.bits {
            false => MsgVal30::Ignored,
            true => MsgVal30::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal30::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal30::Considered
    }
}
#[doc = "Field `MsgVal_30` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal30W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgVal31 {
    #[doc = "0: `0`"]
    Ignored = 0,
    #[doc = "1: `1`"]
    Considered = 1,
}
impl From<MsgVal31> for bool {
    #[inline(always)]
    fn from(variant: MsgVal31) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `MsgVal_31` reader - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal31R = crate::BitReader<MsgVal31>;
impl MsgVal31R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> MsgVal31 {
        match self.bits {
            false => MsgVal31::Ignored,
            true => MsgVal31::Considered,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_ignored(&self) -> bool {
        *self == MsgVal31::Ignored
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_considered(&self) -> bool {
        *self == MsgVal31::Considered
    }
}
#[doc = "Field `MsgVal_31` writer - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
pub type MsgVal31W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_0(&self) -> MsgVal0R {
        MsgVal0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_1(&self) -> MsgVal1R {
        MsgVal1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_2(&self) -> MsgVal2R {
        MsgVal2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_3(&self) -> MsgVal3R {
        MsgVal3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_4(&self) -> MsgVal4R {
        MsgVal4R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_5(&self) -> MsgVal5R {
        MsgVal5R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_6(&self) -> MsgVal6R {
        MsgVal6R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_7(&self) -> MsgVal7R {
        MsgVal7R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_8(&self) -> MsgVal8R {
        MsgVal8R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_9(&self) -> MsgVal9R {
        MsgVal9R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_10(&self) -> MsgVal10R {
        MsgVal10R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_11(&self) -> MsgVal11R {
        MsgVal11R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_12(&self) -> MsgVal12R {
        MsgVal12R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_13(&self) -> MsgVal13R {
        MsgVal13R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_14(&self) -> MsgVal14R {
        MsgVal14R::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_15(&self) -> MsgVal15R {
        MsgVal15R::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_16(&self) -> MsgVal16R {
        MsgVal16R::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_17(&self) -> MsgVal17R {
        MsgVal17R::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_18(&self) -> MsgVal18R {
        MsgVal18R::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_19(&self) -> MsgVal19R {
        MsgVal19R::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_20(&self) -> MsgVal20R {
        MsgVal20R::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_21(&self) -> MsgVal21R {
        MsgVal21R::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_22(&self) -> MsgVal22R {
        MsgVal22R::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_23(&self) -> MsgVal23R {
        MsgVal23R::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_24(&self) -> MsgVal24R {
        MsgVal24R::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_25(&self) -> MsgVal25R {
        MsgVal25R::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_26(&self) -> MsgVal26R {
        MsgVal26R::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_27(&self) -> MsgVal27R {
        MsgVal27R::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 28 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_28(&self) -> MsgVal28R {
        MsgVal28R::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_29(&self) -> MsgVal29R {
        MsgVal29R::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_30(&self) -> MsgVal30R {
        MsgVal30R::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    pub fn msg_val_31(&self) -> MsgVal31R {
        MsgVal31R::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_0(&mut self) -> MsgVal0W<MsghandgrpMovaldSpec> {
        MsgVal0W::new(self, 0)
    }
    #[doc = "Bit 1 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_1(&mut self) -> MsgVal1W<MsghandgrpMovaldSpec> {
        MsgVal1W::new(self, 1)
    }
    #[doc = "Bit 2 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_2(&mut self) -> MsgVal2W<MsghandgrpMovaldSpec> {
        MsgVal2W::new(self, 2)
    }
    #[doc = "Bit 3 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_3(&mut self) -> MsgVal3W<MsghandgrpMovaldSpec> {
        MsgVal3W::new(self, 3)
    }
    #[doc = "Bit 4 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_4(&mut self) -> MsgVal4W<MsghandgrpMovaldSpec> {
        MsgVal4W::new(self, 4)
    }
    #[doc = "Bit 5 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_5(&mut self) -> MsgVal5W<MsghandgrpMovaldSpec> {
        MsgVal5W::new(self, 5)
    }
    #[doc = "Bit 6 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_6(&mut self) -> MsgVal6W<MsghandgrpMovaldSpec> {
        MsgVal6W::new(self, 6)
    }
    #[doc = "Bit 7 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_7(&mut self) -> MsgVal7W<MsghandgrpMovaldSpec> {
        MsgVal7W::new(self, 7)
    }
    #[doc = "Bit 8 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_8(&mut self) -> MsgVal8W<MsghandgrpMovaldSpec> {
        MsgVal8W::new(self, 8)
    }
    #[doc = "Bit 9 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_9(&mut self) -> MsgVal9W<MsghandgrpMovaldSpec> {
        MsgVal9W::new(self, 9)
    }
    #[doc = "Bit 10 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_10(&mut self) -> MsgVal10W<MsghandgrpMovaldSpec> {
        MsgVal10W::new(self, 10)
    }
    #[doc = "Bit 11 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_11(&mut self) -> MsgVal11W<MsghandgrpMovaldSpec> {
        MsgVal11W::new(self, 11)
    }
    #[doc = "Bit 12 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_12(&mut self) -> MsgVal12W<MsghandgrpMovaldSpec> {
        MsgVal12W::new(self, 12)
    }
    #[doc = "Bit 13 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_13(&mut self) -> MsgVal13W<MsghandgrpMovaldSpec> {
        MsgVal13W::new(self, 13)
    }
    #[doc = "Bit 14 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_14(&mut self) -> MsgVal14W<MsghandgrpMovaldSpec> {
        MsgVal14W::new(self, 14)
    }
    #[doc = "Bit 15 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_15(&mut self) -> MsgVal15W<MsghandgrpMovaldSpec> {
        MsgVal15W::new(self, 15)
    }
    #[doc = "Bit 16 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_16(&mut self) -> MsgVal16W<MsghandgrpMovaldSpec> {
        MsgVal16W::new(self, 16)
    }
    #[doc = "Bit 17 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_17(&mut self) -> MsgVal17W<MsghandgrpMovaldSpec> {
        MsgVal17W::new(self, 17)
    }
    #[doc = "Bit 18 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_18(&mut self) -> MsgVal18W<MsghandgrpMovaldSpec> {
        MsgVal18W::new(self, 18)
    }
    #[doc = "Bit 19 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_19(&mut self) -> MsgVal19W<MsghandgrpMovaldSpec> {
        MsgVal19W::new(self, 19)
    }
    #[doc = "Bit 20 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_20(&mut self) -> MsgVal20W<MsghandgrpMovaldSpec> {
        MsgVal20W::new(self, 20)
    }
    #[doc = "Bit 21 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_21(&mut self) -> MsgVal21W<MsghandgrpMovaldSpec> {
        MsgVal21W::new(self, 21)
    }
    #[doc = "Bit 22 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_22(&mut self) -> MsgVal22W<MsghandgrpMovaldSpec> {
        MsgVal22W::new(self, 22)
    }
    #[doc = "Bit 23 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_23(&mut self) -> MsgVal23W<MsghandgrpMovaldSpec> {
        MsgVal23W::new(self, 23)
    }
    #[doc = "Bit 24 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_24(&mut self) -> MsgVal24W<MsghandgrpMovaldSpec> {
        MsgVal24W::new(self, 24)
    }
    #[doc = "Bit 25 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_25(&mut self) -> MsgVal25W<MsghandgrpMovaldSpec> {
        MsgVal25W::new(self, 25)
    }
    #[doc = "Bit 26 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_26(&mut self) -> MsgVal26W<MsghandgrpMovaldSpec> {
        MsgVal26W::new(self, 26)
    }
    #[doc = "Bit 27 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_27(&mut self) -> MsgVal27W<MsghandgrpMovaldSpec> {
        MsgVal27W::new(self, 27)
    }
    #[doc = "Bit 28 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_28(&mut self) -> MsgVal28W<MsghandgrpMovaldSpec> {
        MsgVal28W::new(self, 28)
    }
    #[doc = "Bit 29 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_29(&mut self) -> MsgVal29W<MsghandgrpMovaldSpec> {
        MsgVal29W::new(self, 29)
    }
    #[doc = "Bit 30 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_30(&mut self) -> MsgVal30W<MsghandgrpMovaldSpec> {
        MsgVal30W::new(self, 30)
    }
    #[doc = "Bit 31 - Message valid bits for Message Objects 97 to 128. Array index i corresponds to Message Object i+97."]
    #[inline(always)]
    #[must_use]
    pub fn msg_val_31(&mut self) -> MsgVal31W<MsghandgrpMovaldSpec> {
        MsgVal31W::new(self, 31)
    }
}
#[doc = "Message valid bits for Message Objects 97 to 128. By reading the MsgVal bits, the CPU can check for which Message Object is valid. The MsgVal bit of a specific Message Object can be set/reset by the CPU via the IFx Message Interface Registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_movald::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MsghandgrpMovaldSpec;
impl crate::RegisterSpec for MsghandgrpMovaldSpec {
    type Ux = u32;
    const OFFSET: u64 = 208u64;
}
#[doc = "`read()` method returns [`msghandgrp_movald::R`](R) reader structure"]
impl crate::Readable for MsghandgrpMovaldSpec {}
#[doc = "`reset()` method sets msghandgrp_MOVALD to value 0"]
impl crate::Resettable for MsghandgrpMovaldSpec {
    const RESET_VALUE: u32 = 0;
}
