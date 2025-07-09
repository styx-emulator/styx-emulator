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
#[doc = "Register `msghandgrp_MOIPX` reader"]
pub type R = crate::R<MsghandgrpMoipxSpec>;
#[doc = "Register `msghandgrp_MOIPX` writer"]
pub type W = crate::W<MsghandgrpMoipxSpec>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOIPA register. Array index i corresponds to byte i of the MOIPA register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPndA0 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPndA0> for bool {
    #[inline(always)]
    fn from(variant: IntPndA0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPndA_0` reader - Each bit in this field is a logical OR of a byte of the MOIPA register. Array index i corresponds to byte i of the MOIPA register."]
pub type IntPndA0R = crate::BitReader<IntPndA0>;
impl IntPndA0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPndA0 {
        match self.bits {
            false => IntPndA0::NotSrc,
            true => IntPndA0::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPndA0::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPndA0::Src
    }
}
#[doc = "Field `IntPndA_0` writer - Each bit in this field is a logical OR of a byte of the MOIPA register. Array index i corresponds to byte i of the MOIPA register."]
pub type IntPndA0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOIPA register. Array index i corresponds to byte i of the MOIPA register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPndA1 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPndA1> for bool {
    #[inline(always)]
    fn from(variant: IntPndA1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPndA_1` reader - Each bit in this field is a logical OR of a byte of the MOIPA register. Array index i corresponds to byte i of the MOIPA register."]
pub type IntPndA1R = crate::BitReader<IntPndA1>;
impl IntPndA1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPndA1 {
        match self.bits {
            false => IntPndA1::NotSrc,
            true => IntPndA1::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPndA1::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPndA1::Src
    }
}
#[doc = "Field `IntPndA_1` writer - Each bit in this field is a logical OR of a byte of the MOIPA register. Array index i corresponds to byte i of the MOIPA register."]
pub type IntPndA1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOIPA register. Array index i corresponds to byte i of the MOIPA register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPndA2 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPndA2> for bool {
    #[inline(always)]
    fn from(variant: IntPndA2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPndA_2` reader - Each bit in this field is a logical OR of a byte of the MOIPA register. Array index i corresponds to byte i of the MOIPA register."]
pub type IntPndA2R = crate::BitReader<IntPndA2>;
impl IntPndA2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPndA2 {
        match self.bits {
            false => IntPndA2::NotSrc,
            true => IntPndA2::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPndA2::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPndA2::Src
    }
}
#[doc = "Field `IntPndA_2` writer - Each bit in this field is a logical OR of a byte of the MOIPA register. Array index i corresponds to byte i of the MOIPA register."]
pub type IntPndA2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOIPA register. Array index i corresponds to byte i of the MOIPA register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPndA3 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPndA3> for bool {
    #[inline(always)]
    fn from(variant: IntPndA3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPndA_3` reader - Each bit in this field is a logical OR of a byte of the MOIPA register. Array index i corresponds to byte i of the MOIPA register."]
pub type IntPndA3R = crate::BitReader<IntPndA3>;
impl IntPndA3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPndA3 {
        match self.bits {
            false => IntPndA3::NotSrc,
            true => IntPndA3::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPndA3::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPndA3::Src
    }
}
#[doc = "Field `IntPndA_3` writer - Each bit in this field is a logical OR of a byte of the MOIPA register. Array index i corresponds to byte i of the MOIPA register."]
pub type IntPndA3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOIPB register. Array index i corresponds to byte i of the MOIPB register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPndB0 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPndB0> for bool {
    #[inline(always)]
    fn from(variant: IntPndB0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPndB_0` reader - Each bit in this field is a logical OR of a byte of the MOIPB register. Array index i corresponds to byte i of the MOIPB register."]
pub type IntPndB0R = crate::BitReader<IntPndB0>;
impl IntPndB0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPndB0 {
        match self.bits {
            false => IntPndB0::NotSrc,
            true => IntPndB0::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPndB0::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPndB0::Src
    }
}
#[doc = "Field `IntPndB_0` writer - Each bit in this field is a logical OR of a byte of the MOIPB register. Array index i corresponds to byte i of the MOIPB register."]
pub type IntPndB0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOIPB register. Array index i corresponds to byte i of the MOIPB register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPndB1 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPndB1> for bool {
    #[inline(always)]
    fn from(variant: IntPndB1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPndB_1` reader - Each bit in this field is a logical OR of a byte of the MOIPB register. Array index i corresponds to byte i of the MOIPB register."]
pub type IntPndB1R = crate::BitReader<IntPndB1>;
impl IntPndB1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPndB1 {
        match self.bits {
            false => IntPndB1::NotSrc,
            true => IntPndB1::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPndB1::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPndB1::Src
    }
}
#[doc = "Field `IntPndB_1` writer - Each bit in this field is a logical OR of a byte of the MOIPB register. Array index i corresponds to byte i of the MOIPB register."]
pub type IntPndB1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOIPB register. Array index i corresponds to byte i of the MOIPB register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPndB2 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPndB2> for bool {
    #[inline(always)]
    fn from(variant: IntPndB2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPndB_2` reader - Each bit in this field is a logical OR of a byte of the MOIPB register. Array index i corresponds to byte i of the MOIPB register."]
pub type IntPndB2R = crate::BitReader<IntPndB2>;
impl IntPndB2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPndB2 {
        match self.bits {
            false => IntPndB2::NotSrc,
            true => IntPndB2::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPndB2::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPndB2::Src
    }
}
#[doc = "Field `IntPndB_2` writer - Each bit in this field is a logical OR of a byte of the MOIPB register. Array index i corresponds to byte i of the MOIPB register."]
pub type IntPndB2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOIPB register. Array index i corresponds to byte i of the MOIPB register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPndB3 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPndB3> for bool {
    #[inline(always)]
    fn from(variant: IntPndB3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPndB_3` reader - Each bit in this field is a logical OR of a byte of the MOIPB register. Array index i corresponds to byte i of the MOIPB register."]
pub type IntPndB3R = crate::BitReader<IntPndB3>;
impl IntPndB3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPndB3 {
        match self.bits {
            false => IntPndB3::NotSrc,
            true => IntPndB3::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPndB3::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPndB3::Src
    }
}
#[doc = "Field `IntPndB_3` writer - Each bit in this field is a logical OR of a byte of the MOIPB register. Array index i corresponds to byte i of the MOIPB register."]
pub type IntPndB3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOIPC register. Array index i corresponds to byte i of the MOIPC register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPndC0 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPndC0> for bool {
    #[inline(always)]
    fn from(variant: IntPndC0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPndC_0` reader - Each bit in this field is a logical OR of a byte of the MOIPC register. Array index i corresponds to byte i of the MOIPC register."]
pub type IntPndC0R = crate::BitReader<IntPndC0>;
impl IntPndC0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPndC0 {
        match self.bits {
            false => IntPndC0::NotSrc,
            true => IntPndC0::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPndC0::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPndC0::Src
    }
}
#[doc = "Field `IntPndC_0` writer - Each bit in this field is a logical OR of a byte of the MOIPC register. Array index i corresponds to byte i of the MOIPC register."]
pub type IntPndC0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOIPC register. Array index i corresponds to byte i of the MOIPC register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPndC1 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPndC1> for bool {
    #[inline(always)]
    fn from(variant: IntPndC1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPndC_1` reader - Each bit in this field is a logical OR of a byte of the MOIPC register. Array index i corresponds to byte i of the MOIPC register."]
pub type IntPndC1R = crate::BitReader<IntPndC1>;
impl IntPndC1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPndC1 {
        match self.bits {
            false => IntPndC1::NotSrc,
            true => IntPndC1::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPndC1::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPndC1::Src
    }
}
#[doc = "Field `IntPndC_1` writer - Each bit in this field is a logical OR of a byte of the MOIPC register. Array index i corresponds to byte i of the MOIPC register."]
pub type IntPndC1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOIPC register. Array index i corresponds to byte i of the MOIPC register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPndC2 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPndC2> for bool {
    #[inline(always)]
    fn from(variant: IntPndC2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPndC_2` reader - Each bit in this field is a logical OR of a byte of the MOIPC register. Array index i corresponds to byte i of the MOIPC register."]
pub type IntPndC2R = crate::BitReader<IntPndC2>;
impl IntPndC2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPndC2 {
        match self.bits {
            false => IntPndC2::NotSrc,
            true => IntPndC2::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPndC2::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPndC2::Src
    }
}
#[doc = "Field `IntPndC_2` writer - Each bit in this field is a logical OR of a byte of the MOIPC register. Array index i corresponds to byte i of the MOIPC register."]
pub type IntPndC2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOIPC register. Array index i corresponds to byte i of the MOIPC register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPndC3 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPndC3> for bool {
    #[inline(always)]
    fn from(variant: IntPndC3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPndC_3` reader - Each bit in this field is a logical OR of a byte of the MOIPC register. Array index i corresponds to byte i of the MOIPC register."]
pub type IntPndC3R = crate::BitReader<IntPndC3>;
impl IntPndC3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPndC3 {
        match self.bits {
            false => IntPndC3::NotSrc,
            true => IntPndC3::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPndC3::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPndC3::Src
    }
}
#[doc = "Field `IntPndC_3` writer - Each bit in this field is a logical OR of a byte of the MOIPC register. Array index i corresponds to byte i of the MOIPC register."]
pub type IntPndC3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOIPD register. Array index i corresponds to byte i of the MOIPD register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPndD0 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPndD0> for bool {
    #[inline(always)]
    fn from(variant: IntPndD0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPndD_0` reader - Each bit in this field is a logical OR of a byte of the MOIPD register. Array index i corresponds to byte i of the MOIPD register."]
pub type IntPndD0R = crate::BitReader<IntPndD0>;
impl IntPndD0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPndD0 {
        match self.bits {
            false => IntPndD0::NotSrc,
            true => IntPndD0::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPndD0::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPndD0::Src
    }
}
#[doc = "Field `IntPndD_0` writer - Each bit in this field is a logical OR of a byte of the MOIPD register. Array index i corresponds to byte i of the MOIPD register."]
pub type IntPndD0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOIPD register. Array index i corresponds to byte i of the MOIPD register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPndD1 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPndD1> for bool {
    #[inline(always)]
    fn from(variant: IntPndD1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPndD_1` reader - Each bit in this field is a logical OR of a byte of the MOIPD register. Array index i corresponds to byte i of the MOIPD register."]
pub type IntPndD1R = crate::BitReader<IntPndD1>;
impl IntPndD1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPndD1 {
        match self.bits {
            false => IntPndD1::NotSrc,
            true => IntPndD1::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPndD1::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPndD1::Src
    }
}
#[doc = "Field `IntPndD_1` writer - Each bit in this field is a logical OR of a byte of the MOIPD register. Array index i corresponds to byte i of the MOIPD register."]
pub type IntPndD1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOIPD register. Array index i corresponds to byte i of the MOIPD register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPndD2 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPndD2> for bool {
    #[inline(always)]
    fn from(variant: IntPndD2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPndD_2` reader - Each bit in this field is a logical OR of a byte of the MOIPD register. Array index i corresponds to byte i of the MOIPD register."]
pub type IntPndD2R = crate::BitReader<IntPndD2>;
impl IntPndD2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPndD2 {
        match self.bits {
            false => IntPndD2::NotSrc,
            true => IntPndD2::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPndD2::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPndD2::Src
    }
}
#[doc = "Field `IntPndD_2` writer - Each bit in this field is a logical OR of a byte of the MOIPD register. Array index i corresponds to byte i of the MOIPD register."]
pub type IntPndD2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Each bit in this field is a logical OR of a byte of the MOIPD register. Array index i corresponds to byte i of the MOIPD register.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntPndD3 {
    #[doc = "0: `0`"]
    NotSrc = 0,
    #[doc = "1: `1`"]
    Src = 1,
}
impl From<IntPndD3> for bool {
    #[inline(always)]
    fn from(variant: IntPndD3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `IntPndD_3` reader - Each bit in this field is a logical OR of a byte of the MOIPD register. Array index i corresponds to byte i of the MOIPD register."]
pub type IntPndD3R = crate::BitReader<IntPndD3>;
impl IntPndD3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> IntPndD3 {
        match self.bits {
            false => IntPndD3::NotSrc,
            true => IntPndD3::Src,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_not_src(&self) -> bool {
        *self == IntPndD3::NotSrc
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_src(&self) -> bool {
        *self == IntPndD3::Src
    }
}
#[doc = "Field `IntPndD_3` writer - Each bit in this field is a logical OR of a byte of the MOIPD register. Array index i corresponds to byte i of the MOIPD register."]
pub type IntPndD3W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Each bit in this field is a logical OR of a byte of the MOIPA register. Array index i corresponds to byte i of the MOIPA register."]
    #[inline(always)]
    pub fn int_pnd_a_0(&self) -> IntPndA0R {
        IntPndA0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Each bit in this field is a logical OR of a byte of the MOIPA register. Array index i corresponds to byte i of the MOIPA register."]
    #[inline(always)]
    pub fn int_pnd_a_1(&self) -> IntPndA1R {
        IntPndA1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Each bit in this field is a logical OR of a byte of the MOIPA register. Array index i corresponds to byte i of the MOIPA register."]
    #[inline(always)]
    pub fn int_pnd_a_2(&self) -> IntPndA2R {
        IntPndA2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Each bit in this field is a logical OR of a byte of the MOIPA register. Array index i corresponds to byte i of the MOIPA register."]
    #[inline(always)]
    pub fn int_pnd_a_3(&self) -> IntPndA3R {
        IntPndA3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Each bit in this field is a logical OR of a byte of the MOIPB register. Array index i corresponds to byte i of the MOIPB register."]
    #[inline(always)]
    pub fn int_pnd_b_0(&self) -> IntPndB0R {
        IntPndB0R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Each bit in this field is a logical OR of a byte of the MOIPB register. Array index i corresponds to byte i of the MOIPB register."]
    #[inline(always)]
    pub fn int_pnd_b_1(&self) -> IntPndB1R {
        IntPndB1R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Each bit in this field is a logical OR of a byte of the MOIPB register. Array index i corresponds to byte i of the MOIPB register."]
    #[inline(always)]
    pub fn int_pnd_b_2(&self) -> IntPndB2R {
        IntPndB2R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Each bit in this field is a logical OR of a byte of the MOIPB register. Array index i corresponds to byte i of the MOIPB register."]
    #[inline(always)]
    pub fn int_pnd_b_3(&self) -> IntPndB3R {
        IntPndB3R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Each bit in this field is a logical OR of a byte of the MOIPC register. Array index i corresponds to byte i of the MOIPC register."]
    #[inline(always)]
    pub fn int_pnd_c_0(&self) -> IntPndC0R {
        IntPndC0R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Each bit in this field is a logical OR of a byte of the MOIPC register. Array index i corresponds to byte i of the MOIPC register."]
    #[inline(always)]
    pub fn int_pnd_c_1(&self) -> IntPndC1R {
        IntPndC1R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Each bit in this field is a logical OR of a byte of the MOIPC register. Array index i corresponds to byte i of the MOIPC register."]
    #[inline(always)]
    pub fn int_pnd_c_2(&self) -> IntPndC2R {
        IntPndC2R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Each bit in this field is a logical OR of a byte of the MOIPC register. Array index i corresponds to byte i of the MOIPC register."]
    #[inline(always)]
    pub fn int_pnd_c_3(&self) -> IntPndC3R {
        IntPndC3R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Each bit in this field is a logical OR of a byte of the MOIPD register. Array index i corresponds to byte i of the MOIPD register."]
    #[inline(always)]
    pub fn int_pnd_d_0(&self) -> IntPndD0R {
        IntPndD0R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Each bit in this field is a logical OR of a byte of the MOIPD register. Array index i corresponds to byte i of the MOIPD register."]
    #[inline(always)]
    pub fn int_pnd_d_1(&self) -> IntPndD1R {
        IntPndD1R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Each bit in this field is a logical OR of a byte of the MOIPD register. Array index i corresponds to byte i of the MOIPD register."]
    #[inline(always)]
    pub fn int_pnd_d_2(&self) -> IntPndD2R {
        IntPndD2R::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - Each bit in this field is a logical OR of a byte of the MOIPD register. Array index i corresponds to byte i of the MOIPD register."]
    #[inline(always)]
    pub fn int_pnd_d_3(&self) -> IntPndD3R {
        IntPndD3R::new(((self.bits >> 15) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Each bit in this field is a logical OR of a byte of the MOIPA register. Array index i corresponds to byte i of the MOIPA register."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_a_0(&mut self) -> IntPndA0W<MsghandgrpMoipxSpec> {
        IntPndA0W::new(self, 0)
    }
    #[doc = "Bit 1 - Each bit in this field is a logical OR of a byte of the MOIPA register. Array index i corresponds to byte i of the MOIPA register."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_a_1(&mut self) -> IntPndA1W<MsghandgrpMoipxSpec> {
        IntPndA1W::new(self, 1)
    }
    #[doc = "Bit 2 - Each bit in this field is a logical OR of a byte of the MOIPA register. Array index i corresponds to byte i of the MOIPA register."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_a_2(&mut self) -> IntPndA2W<MsghandgrpMoipxSpec> {
        IntPndA2W::new(self, 2)
    }
    #[doc = "Bit 3 - Each bit in this field is a logical OR of a byte of the MOIPA register. Array index i corresponds to byte i of the MOIPA register."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_a_3(&mut self) -> IntPndA3W<MsghandgrpMoipxSpec> {
        IntPndA3W::new(self, 3)
    }
    #[doc = "Bit 4 - Each bit in this field is a logical OR of a byte of the MOIPB register. Array index i corresponds to byte i of the MOIPB register."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_b_0(&mut self) -> IntPndB0W<MsghandgrpMoipxSpec> {
        IntPndB0W::new(self, 4)
    }
    #[doc = "Bit 5 - Each bit in this field is a logical OR of a byte of the MOIPB register. Array index i corresponds to byte i of the MOIPB register."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_b_1(&mut self) -> IntPndB1W<MsghandgrpMoipxSpec> {
        IntPndB1W::new(self, 5)
    }
    #[doc = "Bit 6 - Each bit in this field is a logical OR of a byte of the MOIPB register. Array index i corresponds to byte i of the MOIPB register."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_b_2(&mut self) -> IntPndB2W<MsghandgrpMoipxSpec> {
        IntPndB2W::new(self, 6)
    }
    #[doc = "Bit 7 - Each bit in this field is a logical OR of a byte of the MOIPB register. Array index i corresponds to byte i of the MOIPB register."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_b_3(&mut self) -> IntPndB3W<MsghandgrpMoipxSpec> {
        IntPndB3W::new(self, 7)
    }
    #[doc = "Bit 8 - Each bit in this field is a logical OR of a byte of the MOIPC register. Array index i corresponds to byte i of the MOIPC register."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_c_0(&mut self) -> IntPndC0W<MsghandgrpMoipxSpec> {
        IntPndC0W::new(self, 8)
    }
    #[doc = "Bit 9 - Each bit in this field is a logical OR of a byte of the MOIPC register. Array index i corresponds to byte i of the MOIPC register."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_c_1(&mut self) -> IntPndC1W<MsghandgrpMoipxSpec> {
        IntPndC1W::new(self, 9)
    }
    #[doc = "Bit 10 - Each bit in this field is a logical OR of a byte of the MOIPC register. Array index i corresponds to byte i of the MOIPC register."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_c_2(&mut self) -> IntPndC2W<MsghandgrpMoipxSpec> {
        IntPndC2W::new(self, 10)
    }
    #[doc = "Bit 11 - Each bit in this field is a logical OR of a byte of the MOIPC register. Array index i corresponds to byte i of the MOIPC register."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_c_3(&mut self) -> IntPndC3W<MsghandgrpMoipxSpec> {
        IntPndC3W::new(self, 11)
    }
    #[doc = "Bit 12 - Each bit in this field is a logical OR of a byte of the MOIPD register. Array index i corresponds to byte i of the MOIPD register."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_d_0(&mut self) -> IntPndD0W<MsghandgrpMoipxSpec> {
        IntPndD0W::new(self, 12)
    }
    #[doc = "Bit 13 - Each bit in this field is a logical OR of a byte of the MOIPD register. Array index i corresponds to byte i of the MOIPD register."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_d_1(&mut self) -> IntPndD1W<MsghandgrpMoipxSpec> {
        IntPndD1W::new(self, 13)
    }
    #[doc = "Bit 14 - Each bit in this field is a logical OR of a byte of the MOIPD register. Array index i corresponds to byte i of the MOIPD register."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_d_2(&mut self) -> IntPndD2W<MsghandgrpMoipxSpec> {
        IntPndD2W::new(self, 14)
    }
    #[doc = "Bit 15 - Each bit in this field is a logical OR of a byte of the MOIPD register. Array index i corresponds to byte i of the MOIPD register."]
    #[inline(always)]
    #[must_use]
    pub fn int_pnd_d_3(&mut self) -> IntPndD3W<MsghandgrpMoipxSpec> {
        IntPndD3W::new(self, 15)
    }
}
#[doc = "Reading this register allows the CPU to quickly detect if any of the interrupt pending bits in each of the MOIPA, MOIPB, MOIPC, and MOIPD Interrupt Pending Registers are set.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`msghandgrp_moipx::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MsghandgrpMoipxSpec;
impl crate::RegisterSpec for MsghandgrpMoipxSpec {
    type Ux = u32;
    const OFFSET: u64 = 172u64;
}
#[doc = "`read()` method returns [`msghandgrp_moipx::R`](R) reader structure"]
impl crate::Readable for MsghandgrpMoipxSpec {}
#[doc = "`reset()` method sets msghandgrp_MOIPX to value 0"]
impl crate::Resettable for MsghandgrpMoipxSpec {
    const RESET_VALUE: u32 = 0;
}
