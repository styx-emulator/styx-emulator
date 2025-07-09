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
#[doc = "Register `devgrp_daint` reader"]
pub type R = crate::R<DevgrpDaintSpec>;
#[doc = "Register `devgrp_daint` writer"]
pub type W = crate::W<DevgrpDaintSpec>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepint0 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Inepint0> for bool {
    #[inline(always)]
    fn from(variant: Inepint0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepint0` reader - "]
pub type Inepint0R = crate::BitReader<Inepint0>;
impl Inepint0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepint0 {
        match self.bits {
            false => Inepint0::Inactive,
            true => Inepint0::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Inepint0::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Inepint0::Active
    }
}
#[doc = "Field `inepint0` writer - "]
pub type Inepint0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepint1 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Inepint1> for bool {
    #[inline(always)]
    fn from(variant: Inepint1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepint1` reader - "]
pub type Inepint1R = crate::BitReader<Inepint1>;
impl Inepint1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepint1 {
        match self.bits {
            false => Inepint1::Inactive,
            true => Inepint1::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Inepint1::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Inepint1::Active
    }
}
#[doc = "Field `inepint1` writer - "]
pub type Inepint1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepint2 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Inepint2> for bool {
    #[inline(always)]
    fn from(variant: Inepint2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepint2` reader - "]
pub type Inepint2R = crate::BitReader<Inepint2>;
impl Inepint2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepint2 {
        match self.bits {
            false => Inepint2::Inactive,
            true => Inepint2::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Inepint2::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Inepint2::Active
    }
}
#[doc = "Field `inepint2` writer - "]
pub type Inepint2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepint3 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Inepint3> for bool {
    #[inline(always)]
    fn from(variant: Inepint3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepint3` reader - "]
pub type Inepint3R = crate::BitReader<Inepint3>;
impl Inepint3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepint3 {
        match self.bits {
            false => Inepint3::Inactive,
            true => Inepint3::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Inepint3::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Inepint3::Active
    }
}
#[doc = "Field `inepint3` writer - "]
pub type Inepint3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepint4 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Inepint4> for bool {
    #[inline(always)]
    fn from(variant: Inepint4) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepint4` reader - "]
pub type Inepint4R = crate::BitReader<Inepint4>;
impl Inepint4R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepint4 {
        match self.bits {
            false => Inepint4::Inactive,
            true => Inepint4::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Inepint4::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Inepint4::Active
    }
}
#[doc = "Field `inepint4` writer - "]
pub type Inepint4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepint5 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Inepint5> for bool {
    #[inline(always)]
    fn from(variant: Inepint5) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepint5` reader - "]
pub type Inepint5R = crate::BitReader<Inepint5>;
impl Inepint5R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepint5 {
        match self.bits {
            false => Inepint5::Inactive,
            true => Inepint5::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Inepint5::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Inepint5::Active
    }
}
#[doc = "Field `inepint5` writer - "]
pub type Inepint5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepint6 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Inepint6> for bool {
    #[inline(always)]
    fn from(variant: Inepint6) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepint6` reader - "]
pub type Inepint6R = crate::BitReader<Inepint6>;
impl Inepint6R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepint6 {
        match self.bits {
            false => Inepint6::Inactive,
            true => Inepint6::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Inepint6::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Inepint6::Active
    }
}
#[doc = "Field `inepint6` writer - "]
pub type Inepint6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepint7 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Inepint7> for bool {
    #[inline(always)]
    fn from(variant: Inepint7) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepint7` reader - "]
pub type Inepint7R = crate::BitReader<Inepint7>;
impl Inepint7R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepint7 {
        match self.bits {
            false => Inepint7::Inactive,
            true => Inepint7::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Inepint7::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Inepint7::Active
    }
}
#[doc = "Field `inepint7` writer - "]
pub type Inepint7W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepint8 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Inepint8> for bool {
    #[inline(always)]
    fn from(variant: Inepint8) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepint8` reader - "]
pub type Inepint8R = crate::BitReader<Inepint8>;
impl Inepint8R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepint8 {
        match self.bits {
            false => Inepint8::Inactive,
            true => Inepint8::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Inepint8::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Inepint8::Active
    }
}
#[doc = "Field `inepint8` writer - "]
pub type Inepint8W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepint9 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Inepint9> for bool {
    #[inline(always)]
    fn from(variant: Inepint9) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepint9` reader - "]
pub type Inepint9R = crate::BitReader<Inepint9>;
impl Inepint9R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepint9 {
        match self.bits {
            false => Inepint9::Inactive,
            true => Inepint9::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Inepint9::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Inepint9::Active
    }
}
#[doc = "Field `inepint9` writer - "]
pub type Inepint9W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepint10 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Inepint10> for bool {
    #[inline(always)]
    fn from(variant: Inepint10) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepint10` reader - "]
pub type Inepint10R = crate::BitReader<Inepint10>;
impl Inepint10R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepint10 {
        match self.bits {
            false => Inepint10::Inactive,
            true => Inepint10::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Inepint10::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Inepint10::Active
    }
}
#[doc = "Field `inepint10` writer - "]
pub type Inepint10W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepint11 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Inepint11> for bool {
    #[inline(always)]
    fn from(variant: Inepint11) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepint11` reader - "]
pub type Inepint11R = crate::BitReader<Inepint11>;
impl Inepint11R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepint11 {
        match self.bits {
            false => Inepint11::Inactive,
            true => Inepint11::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Inepint11::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Inepint11::Active
    }
}
#[doc = "Field `inepint11` writer - "]
pub type Inepint11W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepint12 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Inepint12> for bool {
    #[inline(always)]
    fn from(variant: Inepint12) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepint12` reader - "]
pub type Inepint12R = crate::BitReader<Inepint12>;
impl Inepint12R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepint12 {
        match self.bits {
            false => Inepint12::Inactive,
            true => Inepint12::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Inepint12::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Inepint12::Active
    }
}
#[doc = "Field `inepint12` writer - "]
pub type Inepint12W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepint13 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Inepint13> for bool {
    #[inline(always)]
    fn from(variant: Inepint13) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepint13` reader - "]
pub type Inepint13R = crate::BitReader<Inepint13>;
impl Inepint13R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepint13 {
        match self.bits {
            false => Inepint13::Inactive,
            true => Inepint13::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Inepint13::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Inepint13::Active
    }
}
#[doc = "Field `inepint13` writer - "]
pub type Inepint13W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepint14 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Inepint14> for bool {
    #[inline(always)]
    fn from(variant: Inepint14) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepint14` reader - "]
pub type Inepint14R = crate::BitReader<Inepint14>;
impl Inepint14R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepint14 {
        match self.bits {
            false => Inepint14::Inactive,
            true => Inepint14::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Inepint14::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Inepint14::Active
    }
}
#[doc = "Field `inepint14` writer - "]
pub type Inepint14W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inepint15 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Inepint15> for bool {
    #[inline(always)]
    fn from(variant: Inepint15) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `inepint15` reader - "]
pub type Inepint15R = crate::BitReader<Inepint15>;
impl Inepint15R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Inepint15 {
        match self.bits {
            false => Inepint15::Inactive,
            true => Inepint15::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Inepint15::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Inepint15::Active
    }
}
#[doc = "Field `inepint15` writer - "]
pub type Inepint15W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepint0 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Outepint0> for bool {
    #[inline(always)]
    fn from(variant: Outepint0) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepint0` reader - "]
pub type Outepint0R = crate::BitReader<Outepint0>;
impl Outepint0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepint0 {
        match self.bits {
            false => Outepint0::Inactive,
            true => Outepint0::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Outepint0::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Outepint0::Active
    }
}
#[doc = "Field `outepint0` writer - "]
pub type Outepint0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepint1 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Outepint1> for bool {
    #[inline(always)]
    fn from(variant: Outepint1) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepint1` reader - "]
pub type Outepint1R = crate::BitReader<Outepint1>;
impl Outepint1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepint1 {
        match self.bits {
            false => Outepint1::Inactive,
            true => Outepint1::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Outepint1::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Outepint1::Active
    }
}
#[doc = "Field `outepint1` writer - "]
pub type Outepint1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepint2 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Outepint2> for bool {
    #[inline(always)]
    fn from(variant: Outepint2) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepint2` reader - "]
pub type Outepint2R = crate::BitReader<Outepint2>;
impl Outepint2R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepint2 {
        match self.bits {
            false => Outepint2::Inactive,
            true => Outepint2::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Outepint2::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Outepint2::Active
    }
}
#[doc = "Field `outepint2` writer - "]
pub type Outepint2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepint3 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Outepint3> for bool {
    #[inline(always)]
    fn from(variant: Outepint3) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepint3` reader - "]
pub type Outepint3R = crate::BitReader<Outepint3>;
impl Outepint3R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepint3 {
        match self.bits {
            false => Outepint3::Inactive,
            true => Outepint3::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Outepint3::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Outepint3::Active
    }
}
#[doc = "Field `outepint3` writer - "]
pub type Outepint3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepint4 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Outepint4> for bool {
    #[inline(always)]
    fn from(variant: Outepint4) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepint4` reader - "]
pub type Outepint4R = crate::BitReader<Outepint4>;
impl Outepint4R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepint4 {
        match self.bits {
            false => Outepint4::Inactive,
            true => Outepint4::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Outepint4::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Outepint4::Active
    }
}
#[doc = "Field `outepint4` writer - "]
pub type Outepint4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepint5 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Outepint5> for bool {
    #[inline(always)]
    fn from(variant: Outepint5) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepint5` reader - "]
pub type Outepint5R = crate::BitReader<Outepint5>;
impl Outepint5R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepint5 {
        match self.bits {
            false => Outepint5::Inactive,
            true => Outepint5::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Outepint5::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Outepint5::Active
    }
}
#[doc = "Field `outepint5` writer - "]
pub type Outepint5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepint6 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Outepint6> for bool {
    #[inline(always)]
    fn from(variant: Outepint6) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepint6` reader - "]
pub type Outepint6R = crate::BitReader<Outepint6>;
impl Outepint6R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepint6 {
        match self.bits {
            false => Outepint6::Inactive,
            true => Outepint6::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Outepint6::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Outepint6::Active
    }
}
#[doc = "Field `outepint6` writer - "]
pub type Outepint6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepint7 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Outepint7> for bool {
    #[inline(always)]
    fn from(variant: Outepint7) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepint7` reader - "]
pub type Outepint7R = crate::BitReader<Outepint7>;
impl Outepint7R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepint7 {
        match self.bits {
            false => Outepint7::Inactive,
            true => Outepint7::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Outepint7::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Outepint7::Active
    }
}
#[doc = "Field `outepint7` writer - "]
pub type Outepint7W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepint8 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Outepint8> for bool {
    #[inline(always)]
    fn from(variant: Outepint8) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepint8` reader - "]
pub type Outepint8R = crate::BitReader<Outepint8>;
impl Outepint8R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepint8 {
        match self.bits {
            false => Outepint8::Inactive,
            true => Outepint8::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Outepint8::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Outepint8::Active
    }
}
#[doc = "Field `outepint8` writer - "]
pub type Outepint8W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepint9 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Outepint9> for bool {
    #[inline(always)]
    fn from(variant: Outepint9) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepint9` reader - "]
pub type Outepint9R = crate::BitReader<Outepint9>;
impl Outepint9R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepint9 {
        match self.bits {
            false => Outepint9::Inactive,
            true => Outepint9::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Outepint9::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Outepint9::Active
    }
}
#[doc = "Field `outepint9` writer - "]
pub type Outepint9W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepint10 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Outepint10> for bool {
    #[inline(always)]
    fn from(variant: Outepint10) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepint10` reader - "]
pub type Outepint10R = crate::BitReader<Outepint10>;
impl Outepint10R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepint10 {
        match self.bits {
            false => Outepint10::Inactive,
            true => Outepint10::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Outepint10::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Outepint10::Active
    }
}
#[doc = "Field `outepint10` writer - "]
pub type Outepint10W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepint11 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Outepint11> for bool {
    #[inline(always)]
    fn from(variant: Outepint11) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepint11` reader - "]
pub type Outepint11R = crate::BitReader<Outepint11>;
impl Outepint11R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepint11 {
        match self.bits {
            false => Outepint11::Inactive,
            true => Outepint11::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Outepint11::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Outepint11::Active
    }
}
#[doc = "Field `outepint11` writer - "]
pub type Outepint11W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepint12 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Outepint12> for bool {
    #[inline(always)]
    fn from(variant: Outepint12) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepint12` reader - "]
pub type Outepint12R = crate::BitReader<Outepint12>;
impl Outepint12R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepint12 {
        match self.bits {
            false => Outepint12::Inactive,
            true => Outepint12::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Outepint12::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Outepint12::Active
    }
}
#[doc = "Field `outepint12` writer - "]
pub type Outepint12W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepint13 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Outepint13> for bool {
    #[inline(always)]
    fn from(variant: Outepint13) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepint13` reader - "]
pub type Outepint13R = crate::BitReader<Outepint13>;
impl Outepint13R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepint13 {
        match self.bits {
            false => Outepint13::Inactive,
            true => Outepint13::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Outepint13::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Outepint13::Active
    }
}
#[doc = "Field `outepint13` writer - "]
pub type Outepint13W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepint14 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Outepint14> for bool {
    #[inline(always)]
    fn from(variant: Outepint14) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepint14` reader - "]
pub type Outepint14R = crate::BitReader<Outepint14>;
impl Outepint14R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepint14 {
        match self.bits {
            false => Outepint14::Inactive,
            true => Outepint14::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Outepint14::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Outepint14::Active
    }
}
#[doc = "Field `outepint14` writer - "]
pub type Outepint14W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outepint15 {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Outepint15> for bool {
    #[inline(always)]
    fn from(variant: Outepint15) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `outepint15` reader - "]
pub type Outepint15R = crate::BitReader<Outepint15>;
impl Outepint15R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Outepint15 {
        match self.bits {
            false => Outepint15::Inactive,
            true => Outepint15::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Outepint15::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Outepint15::Active
    }
}
#[doc = "Field `outepint15` writer - "]
pub type Outepint15W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0"]
    #[inline(always)]
    pub fn inepint0(&self) -> Inepint0R {
        Inepint0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1"]
    #[inline(always)]
    pub fn inepint1(&self) -> Inepint1R {
        Inepint1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2"]
    #[inline(always)]
    pub fn inepint2(&self) -> Inepint2R {
        Inepint2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3"]
    #[inline(always)]
    pub fn inepint3(&self) -> Inepint3R {
        Inepint3R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4"]
    #[inline(always)]
    pub fn inepint4(&self) -> Inepint4R {
        Inepint4R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5"]
    #[inline(always)]
    pub fn inepint5(&self) -> Inepint5R {
        Inepint5R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6"]
    #[inline(always)]
    pub fn inepint6(&self) -> Inepint6R {
        Inepint6R::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7"]
    #[inline(always)]
    pub fn inepint7(&self) -> Inepint7R {
        Inepint7R::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8"]
    #[inline(always)]
    pub fn inepint8(&self) -> Inepint8R {
        Inepint8R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9"]
    #[inline(always)]
    pub fn inepint9(&self) -> Inepint9R {
        Inepint9R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10"]
    #[inline(always)]
    pub fn inepint10(&self) -> Inepint10R {
        Inepint10R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11"]
    #[inline(always)]
    pub fn inepint11(&self) -> Inepint11R {
        Inepint11R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12"]
    #[inline(always)]
    pub fn inepint12(&self) -> Inepint12R {
        Inepint12R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13"]
    #[inline(always)]
    pub fn inepint13(&self) -> Inepint13R {
        Inepint13R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14"]
    #[inline(always)]
    pub fn inepint14(&self) -> Inepint14R {
        Inepint14R::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15"]
    #[inline(always)]
    pub fn inepint15(&self) -> Inepint15R {
        Inepint15R::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16"]
    #[inline(always)]
    pub fn outepint0(&self) -> Outepint0R {
        Outepint0R::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17"]
    #[inline(always)]
    pub fn outepint1(&self) -> Outepint1R {
        Outepint1R::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18"]
    #[inline(always)]
    pub fn outepint2(&self) -> Outepint2R {
        Outepint2R::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19"]
    #[inline(always)]
    pub fn outepint3(&self) -> Outepint3R {
        Outepint3R::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20"]
    #[inline(always)]
    pub fn outepint4(&self) -> Outepint4R {
        Outepint4R::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21"]
    #[inline(always)]
    pub fn outepint5(&self) -> Outepint5R {
        Outepint5R::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22"]
    #[inline(always)]
    pub fn outepint6(&self) -> Outepint6R {
        Outepint6R::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23"]
    #[inline(always)]
    pub fn outepint7(&self) -> Outepint7R {
        Outepint7R::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24"]
    #[inline(always)]
    pub fn outepint8(&self) -> Outepint8R {
        Outepint8R::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25"]
    #[inline(always)]
    pub fn outepint9(&self) -> Outepint9R {
        Outepint9R::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26"]
    #[inline(always)]
    pub fn outepint10(&self) -> Outepint10R {
        Outepint10R::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27"]
    #[inline(always)]
    pub fn outepint11(&self) -> Outepint11R {
        Outepint11R::new(((self.bits >> 27) & 1) != 0)
    }
    #[doc = "Bit 28"]
    #[inline(always)]
    pub fn outepint12(&self) -> Outepint12R {
        Outepint12R::new(((self.bits >> 28) & 1) != 0)
    }
    #[doc = "Bit 29"]
    #[inline(always)]
    pub fn outepint13(&self) -> Outepint13R {
        Outepint13R::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30"]
    #[inline(always)]
    pub fn outepint14(&self) -> Outepint14R {
        Outepint14R::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31"]
    #[inline(always)]
    pub fn outepint15(&self) -> Outepint15R {
        Outepint15R::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0"]
    #[inline(always)]
    #[must_use]
    pub fn inepint0(&mut self) -> Inepint0W<DevgrpDaintSpec> {
        Inepint0W::new(self, 0)
    }
    #[doc = "Bit 1"]
    #[inline(always)]
    #[must_use]
    pub fn inepint1(&mut self) -> Inepint1W<DevgrpDaintSpec> {
        Inepint1W::new(self, 1)
    }
    #[doc = "Bit 2"]
    #[inline(always)]
    #[must_use]
    pub fn inepint2(&mut self) -> Inepint2W<DevgrpDaintSpec> {
        Inepint2W::new(self, 2)
    }
    #[doc = "Bit 3"]
    #[inline(always)]
    #[must_use]
    pub fn inepint3(&mut self) -> Inepint3W<DevgrpDaintSpec> {
        Inepint3W::new(self, 3)
    }
    #[doc = "Bit 4"]
    #[inline(always)]
    #[must_use]
    pub fn inepint4(&mut self) -> Inepint4W<DevgrpDaintSpec> {
        Inepint4W::new(self, 4)
    }
    #[doc = "Bit 5"]
    #[inline(always)]
    #[must_use]
    pub fn inepint5(&mut self) -> Inepint5W<DevgrpDaintSpec> {
        Inepint5W::new(self, 5)
    }
    #[doc = "Bit 6"]
    #[inline(always)]
    #[must_use]
    pub fn inepint6(&mut self) -> Inepint6W<DevgrpDaintSpec> {
        Inepint6W::new(self, 6)
    }
    #[doc = "Bit 7"]
    #[inline(always)]
    #[must_use]
    pub fn inepint7(&mut self) -> Inepint7W<DevgrpDaintSpec> {
        Inepint7W::new(self, 7)
    }
    #[doc = "Bit 8"]
    #[inline(always)]
    #[must_use]
    pub fn inepint8(&mut self) -> Inepint8W<DevgrpDaintSpec> {
        Inepint8W::new(self, 8)
    }
    #[doc = "Bit 9"]
    #[inline(always)]
    #[must_use]
    pub fn inepint9(&mut self) -> Inepint9W<DevgrpDaintSpec> {
        Inepint9W::new(self, 9)
    }
    #[doc = "Bit 10"]
    #[inline(always)]
    #[must_use]
    pub fn inepint10(&mut self) -> Inepint10W<DevgrpDaintSpec> {
        Inepint10W::new(self, 10)
    }
    #[doc = "Bit 11"]
    #[inline(always)]
    #[must_use]
    pub fn inepint11(&mut self) -> Inepint11W<DevgrpDaintSpec> {
        Inepint11W::new(self, 11)
    }
    #[doc = "Bit 12"]
    #[inline(always)]
    #[must_use]
    pub fn inepint12(&mut self) -> Inepint12W<DevgrpDaintSpec> {
        Inepint12W::new(self, 12)
    }
    #[doc = "Bit 13"]
    #[inline(always)]
    #[must_use]
    pub fn inepint13(&mut self) -> Inepint13W<DevgrpDaintSpec> {
        Inepint13W::new(self, 13)
    }
    #[doc = "Bit 14"]
    #[inline(always)]
    #[must_use]
    pub fn inepint14(&mut self) -> Inepint14W<DevgrpDaintSpec> {
        Inepint14W::new(self, 14)
    }
    #[doc = "Bit 15"]
    #[inline(always)]
    #[must_use]
    pub fn inepint15(&mut self) -> Inepint15W<DevgrpDaintSpec> {
        Inepint15W::new(self, 15)
    }
    #[doc = "Bit 16"]
    #[inline(always)]
    #[must_use]
    pub fn outepint0(&mut self) -> Outepint0W<DevgrpDaintSpec> {
        Outepint0W::new(self, 16)
    }
    #[doc = "Bit 17"]
    #[inline(always)]
    #[must_use]
    pub fn outepint1(&mut self) -> Outepint1W<DevgrpDaintSpec> {
        Outepint1W::new(self, 17)
    }
    #[doc = "Bit 18"]
    #[inline(always)]
    #[must_use]
    pub fn outepint2(&mut self) -> Outepint2W<DevgrpDaintSpec> {
        Outepint2W::new(self, 18)
    }
    #[doc = "Bit 19"]
    #[inline(always)]
    #[must_use]
    pub fn outepint3(&mut self) -> Outepint3W<DevgrpDaintSpec> {
        Outepint3W::new(self, 19)
    }
    #[doc = "Bit 20"]
    #[inline(always)]
    #[must_use]
    pub fn outepint4(&mut self) -> Outepint4W<DevgrpDaintSpec> {
        Outepint4W::new(self, 20)
    }
    #[doc = "Bit 21"]
    #[inline(always)]
    #[must_use]
    pub fn outepint5(&mut self) -> Outepint5W<DevgrpDaintSpec> {
        Outepint5W::new(self, 21)
    }
    #[doc = "Bit 22"]
    #[inline(always)]
    #[must_use]
    pub fn outepint6(&mut self) -> Outepint6W<DevgrpDaintSpec> {
        Outepint6W::new(self, 22)
    }
    #[doc = "Bit 23"]
    #[inline(always)]
    #[must_use]
    pub fn outepint7(&mut self) -> Outepint7W<DevgrpDaintSpec> {
        Outepint7W::new(self, 23)
    }
    #[doc = "Bit 24"]
    #[inline(always)]
    #[must_use]
    pub fn outepint8(&mut self) -> Outepint8W<DevgrpDaintSpec> {
        Outepint8W::new(self, 24)
    }
    #[doc = "Bit 25"]
    #[inline(always)]
    #[must_use]
    pub fn outepint9(&mut self) -> Outepint9W<DevgrpDaintSpec> {
        Outepint9W::new(self, 25)
    }
    #[doc = "Bit 26"]
    #[inline(always)]
    #[must_use]
    pub fn outepint10(&mut self) -> Outepint10W<DevgrpDaintSpec> {
        Outepint10W::new(self, 26)
    }
    #[doc = "Bit 27"]
    #[inline(always)]
    #[must_use]
    pub fn outepint11(&mut self) -> Outepint11W<DevgrpDaintSpec> {
        Outepint11W::new(self, 27)
    }
    #[doc = "Bit 28"]
    #[inline(always)]
    #[must_use]
    pub fn outepint12(&mut self) -> Outepint12W<DevgrpDaintSpec> {
        Outepint12W::new(self, 28)
    }
    #[doc = "Bit 29"]
    #[inline(always)]
    #[must_use]
    pub fn outepint13(&mut self) -> Outepint13W<DevgrpDaintSpec> {
        Outepint13W::new(self, 29)
    }
    #[doc = "Bit 30"]
    #[inline(always)]
    #[must_use]
    pub fn outepint14(&mut self) -> Outepint14W<DevgrpDaintSpec> {
        Outepint14W::new(self, 30)
    }
    #[doc = "Bit 31"]
    #[inline(always)]
    #[must_use]
    pub fn outepint15(&mut self) -> Outepint15W<DevgrpDaintSpec> {
        Outepint15W::new(self, 31)
    }
}
#[doc = "When a significant event occurs on an endpoint, a Device All Endpoints Interrupt register interrupts the application using the Device OUT Endpoints Interrupt bit or Device IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively). This is shown in Figure 5-2. There is one interrupt bit per endpoint, up to a maximum of 16 bits for OUT endpoints and 16 bits for IN endpoints. for a bidirectional endpoint, the corresponding IN and OUT interrupt bits are used. Bits in this register are set and cleared when the application sets and clears bits in the corresponding Device Endpoint-n Interrupt register (DIEPINTn/DOEPINTn).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_daint::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDaintSpec;
impl crate::RegisterSpec for DevgrpDaintSpec {
    type Ux = u32;
    const OFFSET: u64 = 2072u64;
}
#[doc = "`read()` method returns [`devgrp_daint::R`](R) reader structure"]
impl crate::Readable for DevgrpDaintSpec {}
#[doc = "`reset()` method sets devgrp_daint to value 0"]
impl crate::Resettable for DevgrpDaintSpec {
    const RESET_VALUE: u32 = 0;
}
