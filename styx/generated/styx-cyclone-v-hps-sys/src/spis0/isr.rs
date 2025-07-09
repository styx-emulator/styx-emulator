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
#[doc = "Register `isr` reader"]
pub type R = crate::R<IsrSpec>;
#[doc = "Register `isr` writer"]
pub type W = crate::W<IsrSpec>;
#[doc = "Empty Status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txeis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Txeis> for bool {
    #[inline(always)]
    fn from(variant: Txeis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txeis` reader - Empty Status."]
pub type TxeisR = crate::BitReader<Txeis>;
impl TxeisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txeis {
        match self.bits {
            false => Txeis::Inactive,
            true => Txeis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Txeis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Txeis::Active
    }
}
#[doc = "Field `txeis` writer - Empty Status."]
pub type TxeisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Overflow Status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Txois {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Txois> for bool {
    #[inline(always)]
    fn from(variant: Txois) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `txois` reader - Overflow Status."]
pub type TxoisR = crate::BitReader<Txois>;
impl TxoisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Txois {
        match self.bits {
            false => Txois::Inactive,
            true => Txois::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Txois::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Txois::Active
    }
}
#[doc = "Field `txois` writer - Overflow Status."]
pub type TxoisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Underflow Status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxuis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxuis> for bool {
    #[inline(always)]
    fn from(variant: Rxuis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxuis` reader - Underflow Status."]
pub type RxuisR = crate::BitReader<Rxuis>;
impl RxuisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxuis {
        match self.bits {
            false => Rxuis::Inactive,
            true => Rxuis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxuis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxuis::Active
    }
}
#[doc = "Field `rxuis` writer - Underflow Status."]
pub type RxuisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Overflow Status.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxois {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxois> for bool {
    #[inline(always)]
    fn from(variant: Rxois) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxois` reader - Overflow Status."]
pub type RxoisR = crate::BitReader<Rxois>;
impl RxoisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxois {
        match self.bits {
            false => Rxois::Inactive,
            true => Rxois::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxois::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxois::Active
    }
}
#[doc = "Field `rxois` writer - Overflow Status."]
pub type RxoisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Full Status\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rxfis {
    #[doc = "0: `0`"]
    Inactive = 0,
    #[doc = "1: `1`"]
    Active = 1,
}
impl From<Rxfis> for bool {
    #[inline(always)]
    fn from(variant: Rxfis) -> Self {
        variant as u8 != 0
    }
}
#[doc = "Field `rxfis` reader - Full Status"]
pub type RxfisR = crate::BitReader<Rxfis>;
impl RxfisR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Rxfis {
        match self.bits {
            false => Rxfis::Inactive,
            true => Rxfis::Active,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_inactive(&self) -> bool {
        *self == Rxfis::Inactive
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        *self == Rxfis::Active
    }
}
#[doc = "Field `rxfis` writer - Full Status"]
pub type RxfisW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Empty Status."]
    #[inline(always)]
    pub fn txeis(&self) -> TxeisR {
        TxeisR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Overflow Status."]
    #[inline(always)]
    pub fn txois(&self) -> TxoisR {
        TxoisR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Underflow Status."]
    #[inline(always)]
    pub fn rxuis(&self) -> RxuisR {
        RxuisR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Overflow Status."]
    #[inline(always)]
    pub fn rxois(&self) -> RxoisR {
        RxoisR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Full Status"]
    #[inline(always)]
    pub fn rxfis(&self) -> RxfisR {
        RxfisR::new(((self.bits >> 4) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Empty Status."]
    #[inline(always)]
    #[must_use]
    pub fn txeis(&mut self) -> TxeisW<IsrSpec> {
        TxeisW::new(self, 0)
    }
    #[doc = "Bit 1 - Overflow Status."]
    #[inline(always)]
    #[must_use]
    pub fn txois(&mut self) -> TxoisW<IsrSpec> {
        TxoisW::new(self, 1)
    }
    #[doc = "Bit 2 - Underflow Status."]
    #[inline(always)]
    #[must_use]
    pub fn rxuis(&mut self) -> RxuisW<IsrSpec> {
        RxuisW::new(self, 2)
    }
    #[doc = "Bit 3 - Overflow Status."]
    #[inline(always)]
    #[must_use]
    pub fn rxois(&mut self) -> RxoisW<IsrSpec> {
        RxoisW::new(self, 3)
    }
    #[doc = "Bit 4 - Full Status"]
    #[inline(always)]
    #[must_use]
    pub fn rxfis(&mut self) -> RxfisW<IsrSpec> {
        RxfisW::new(self, 4)
    }
}
#[doc = "This register reports the status of the SPI Slave interrupts after they have been masked.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`isr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IsrSpec;
impl crate::RegisterSpec for IsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 48u64;
}
#[doc = "`read()` method returns [`isr::R`](R) reader structure"]
impl crate::Readable for IsrSpec {}
#[doc = "`reset()` method sets isr to value 0"]
impl crate::Resettable for IsrSpec {
    const RESET_VALUE: u32 = 0;
}
