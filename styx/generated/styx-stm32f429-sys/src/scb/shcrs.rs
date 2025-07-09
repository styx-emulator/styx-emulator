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
#[doc = "Register `SHCRS` reader"]
pub type R = crate::R<ShcrsSpec>;
#[doc = "Register `SHCRS` writer"]
pub type W = crate::W<ShcrsSpec>;
#[doc = "Field `MEMFAULTACT` reader - Memory management fault exception active bit"]
pub type MemfaultactR = crate::BitReader;
#[doc = "Field `MEMFAULTACT` writer - Memory management fault exception active bit"]
pub type MemfaultactW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BUSFAULTACT` reader - Bus fault exception active bit"]
pub type BusfaultactR = crate::BitReader;
#[doc = "Field `BUSFAULTACT` writer - Bus fault exception active bit"]
pub type BusfaultactW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `USGFAULTACT` reader - Usage fault exception active bit"]
pub type UsgfaultactR = crate::BitReader;
#[doc = "Field `USGFAULTACT` writer - Usage fault exception active bit"]
pub type UsgfaultactW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SVCALLACT` reader - SVC call active bit"]
pub type SvcallactR = crate::BitReader;
#[doc = "Field `SVCALLACT` writer - SVC call active bit"]
pub type SvcallactW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MONITORACT` reader - Debug monitor active bit"]
pub type MonitoractR = crate::BitReader;
#[doc = "Field `MONITORACT` writer - Debug monitor active bit"]
pub type MonitoractW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PENDSVACT` reader - PendSV exception active bit"]
pub type PendsvactR = crate::BitReader;
#[doc = "Field `PENDSVACT` writer - PendSV exception active bit"]
pub type PendsvactW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SYSTICKACT` reader - SysTick exception active bit"]
pub type SystickactR = crate::BitReader;
#[doc = "Field `SYSTICKACT` writer - SysTick exception active bit"]
pub type SystickactW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `USGFAULTPENDED` reader - Usage fault exception pending bit"]
pub type UsgfaultpendedR = crate::BitReader;
#[doc = "Field `USGFAULTPENDED` writer - Usage fault exception pending bit"]
pub type UsgfaultpendedW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MEMFAULTPENDED` reader - Memory management fault exception pending bit"]
pub type MemfaultpendedR = crate::BitReader;
#[doc = "Field `MEMFAULTPENDED` writer - Memory management fault exception pending bit"]
pub type MemfaultpendedW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BUSFAULTPENDED` reader - Bus fault exception pending bit"]
pub type BusfaultpendedR = crate::BitReader;
#[doc = "Field `BUSFAULTPENDED` writer - Bus fault exception pending bit"]
pub type BusfaultpendedW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SVCALLPENDED` reader - SVC call pending bit"]
pub type SvcallpendedR = crate::BitReader;
#[doc = "Field `SVCALLPENDED` writer - SVC call pending bit"]
pub type SvcallpendedW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MEMFAULTENA` reader - Memory management fault enable bit"]
pub type MemfaultenaR = crate::BitReader;
#[doc = "Field `MEMFAULTENA` writer - Memory management fault enable bit"]
pub type MemfaultenaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BUSFAULTENA` reader - Bus fault enable bit"]
pub type BusfaultenaR = crate::BitReader;
#[doc = "Field `BUSFAULTENA` writer - Bus fault enable bit"]
pub type BusfaultenaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `USGFAULTENA` reader - Usage fault enable bit"]
pub type UsgfaultenaR = crate::BitReader;
#[doc = "Field `USGFAULTENA` writer - Usage fault enable bit"]
pub type UsgfaultenaW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Memory management fault exception active bit"]
    #[inline(always)]
    pub fn memfaultact(&self) -> MemfaultactR {
        MemfaultactR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Bus fault exception active bit"]
    #[inline(always)]
    pub fn busfaultact(&self) -> BusfaultactR {
        BusfaultactR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 3 - Usage fault exception active bit"]
    #[inline(always)]
    pub fn usgfaultact(&self) -> UsgfaultactR {
        UsgfaultactR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 7 - SVC call active bit"]
    #[inline(always)]
    pub fn svcallact(&self) -> SvcallactR {
        SvcallactR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - Debug monitor active bit"]
    #[inline(always)]
    pub fn monitoract(&self) -> MonitoractR {
        MonitoractR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 10 - PendSV exception active bit"]
    #[inline(always)]
    pub fn pendsvact(&self) -> PendsvactR {
        PendsvactR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - SysTick exception active bit"]
    #[inline(always)]
    pub fn systickact(&self) -> SystickactR {
        SystickactR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Usage fault exception pending bit"]
    #[inline(always)]
    pub fn usgfaultpended(&self) -> UsgfaultpendedR {
        UsgfaultpendedR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Memory management fault exception pending bit"]
    #[inline(always)]
    pub fn memfaultpended(&self) -> MemfaultpendedR {
        MemfaultpendedR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Bus fault exception pending bit"]
    #[inline(always)]
    pub fn busfaultpended(&self) -> BusfaultpendedR {
        BusfaultpendedR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - SVC call pending bit"]
    #[inline(always)]
    pub fn svcallpended(&self) -> SvcallpendedR {
        SvcallpendedR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - Memory management fault enable bit"]
    #[inline(always)]
    pub fn memfaultena(&self) -> MemfaultenaR {
        MemfaultenaR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Bus fault enable bit"]
    #[inline(always)]
    pub fn busfaultena(&self) -> BusfaultenaR {
        BusfaultenaR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Usage fault enable bit"]
    #[inline(always)]
    pub fn usgfaultena(&self) -> UsgfaultenaR {
        UsgfaultenaR::new(((self.bits >> 18) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Memory management fault exception active bit"]
    #[inline(always)]
    #[must_use]
    pub fn memfaultact(&mut self) -> MemfaultactW<ShcrsSpec> {
        MemfaultactW::new(self, 0)
    }
    #[doc = "Bit 1 - Bus fault exception active bit"]
    #[inline(always)]
    #[must_use]
    pub fn busfaultact(&mut self) -> BusfaultactW<ShcrsSpec> {
        BusfaultactW::new(self, 1)
    }
    #[doc = "Bit 3 - Usage fault exception active bit"]
    #[inline(always)]
    #[must_use]
    pub fn usgfaultact(&mut self) -> UsgfaultactW<ShcrsSpec> {
        UsgfaultactW::new(self, 3)
    }
    #[doc = "Bit 7 - SVC call active bit"]
    #[inline(always)]
    #[must_use]
    pub fn svcallact(&mut self) -> SvcallactW<ShcrsSpec> {
        SvcallactW::new(self, 7)
    }
    #[doc = "Bit 8 - Debug monitor active bit"]
    #[inline(always)]
    #[must_use]
    pub fn monitoract(&mut self) -> MonitoractW<ShcrsSpec> {
        MonitoractW::new(self, 8)
    }
    #[doc = "Bit 10 - PendSV exception active bit"]
    #[inline(always)]
    #[must_use]
    pub fn pendsvact(&mut self) -> PendsvactW<ShcrsSpec> {
        PendsvactW::new(self, 10)
    }
    #[doc = "Bit 11 - SysTick exception active bit"]
    #[inline(always)]
    #[must_use]
    pub fn systickact(&mut self) -> SystickactW<ShcrsSpec> {
        SystickactW::new(self, 11)
    }
    #[doc = "Bit 12 - Usage fault exception pending bit"]
    #[inline(always)]
    #[must_use]
    pub fn usgfaultpended(&mut self) -> UsgfaultpendedW<ShcrsSpec> {
        UsgfaultpendedW::new(self, 12)
    }
    #[doc = "Bit 13 - Memory management fault exception pending bit"]
    #[inline(always)]
    #[must_use]
    pub fn memfaultpended(&mut self) -> MemfaultpendedW<ShcrsSpec> {
        MemfaultpendedW::new(self, 13)
    }
    #[doc = "Bit 14 - Bus fault exception pending bit"]
    #[inline(always)]
    #[must_use]
    pub fn busfaultpended(&mut self) -> BusfaultpendedW<ShcrsSpec> {
        BusfaultpendedW::new(self, 14)
    }
    #[doc = "Bit 15 - SVC call pending bit"]
    #[inline(always)]
    #[must_use]
    pub fn svcallpended(&mut self) -> SvcallpendedW<ShcrsSpec> {
        SvcallpendedW::new(self, 15)
    }
    #[doc = "Bit 16 - Memory management fault enable bit"]
    #[inline(always)]
    #[must_use]
    pub fn memfaultena(&mut self) -> MemfaultenaW<ShcrsSpec> {
        MemfaultenaW::new(self, 16)
    }
    #[doc = "Bit 17 - Bus fault enable bit"]
    #[inline(always)]
    #[must_use]
    pub fn busfaultena(&mut self) -> BusfaultenaW<ShcrsSpec> {
        BusfaultenaW::new(self, 17)
    }
    #[doc = "Bit 18 - Usage fault enable bit"]
    #[inline(always)]
    #[must_use]
    pub fn usgfaultena(&mut self) -> UsgfaultenaW<ShcrsSpec> {
        UsgfaultenaW::new(self, 18)
    }
}
#[doc = "System handler control and state register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`shcrs::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`shcrs::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ShcrsSpec;
impl crate::RegisterSpec for ShcrsSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`shcrs::R`](R) reader structure"]
impl crate::Readable for ShcrsSpec {}
#[doc = "`write(|w| ..)` method takes [`shcrs::W`](W) writer structure"]
impl crate::Writable for ShcrsSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SHCRS to value 0"]
impl crate::Resettable for ShcrsSpec {
    const RESET_VALUE: u32 = 0;
}
