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
#[doc = "Register `CR2` reader"]
pub type R = crate::R<Cr2Spec>;
#[doc = "Register `CR2` writer"]
pub type W = crate::W<Cr2Spec>;
#[doc = "Field `CWUPF1` reader - Clear Wakeup Pin flag for PA0"]
pub type Cwupf1R = crate::BitReader;
#[doc = "Field `CWUPF1` writer - Clear Wakeup Pin flag for PA0"]
pub type Cwupf1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CWUPF2` reader - Clear Wakeup Pin flag for PA2"]
pub type Cwupf2R = crate::BitReader;
#[doc = "Field `CWUPF2` writer - Clear Wakeup Pin flag for PA2"]
pub type Cwupf2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CWUPF3` reader - Clear Wakeup Pin flag for PC1"]
pub type Cwupf3R = crate::BitReader;
#[doc = "Field `CWUPF3` writer - Clear Wakeup Pin flag for PC1"]
pub type Cwupf3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CWUPF4` reader - Clear Wakeup Pin flag for PC13"]
pub type Cwupf4R = crate::BitReader;
#[doc = "Field `CWUPF4` writer - Clear Wakeup Pin flag for PC13"]
pub type Cwupf4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CWUPF5` reader - Clear Wakeup Pin flag for PI8"]
pub type Cwupf5R = crate::BitReader;
#[doc = "Field `CWUPF5` writer - Clear Wakeup Pin flag for PI8"]
pub type Cwupf5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CWUPF6` reader - Clear Wakeup Pin flag for PI11"]
pub type Cwupf6R = crate::BitReader;
#[doc = "Field `CWUPF6` writer - Clear Wakeup Pin flag for PI11"]
pub type Cwupf6W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WUPP1` reader - Wakeup pin polarity bit for PA0"]
pub type Wupp1R = crate::BitReader;
#[doc = "Field `WUPP1` writer - Wakeup pin polarity bit for PA0"]
pub type Wupp1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WUPP2` reader - Wakeup pin polarity bit for PA2"]
pub type Wupp2R = crate::BitReader;
#[doc = "Field `WUPP2` writer - Wakeup pin polarity bit for PA2"]
pub type Wupp2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WUPP3` reader - Wakeup pin polarity bit for PC1"]
pub type Wupp3R = crate::BitReader;
#[doc = "Field `WUPP3` writer - Wakeup pin polarity bit for PC1"]
pub type Wupp3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WUPP4` reader - Wakeup pin polarity bit for PC13"]
pub type Wupp4R = crate::BitReader;
#[doc = "Field `WUPP4` writer - Wakeup pin polarity bit for PC13"]
pub type Wupp4W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WUPP5` reader - Wakeup pin polarity bit for PI8"]
pub type Wupp5R = crate::BitReader;
#[doc = "Field `WUPP5` writer - Wakeup pin polarity bit for PI8"]
pub type Wupp5W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `WUPP6` reader - Wakeup pin polarity bit for PI11"]
pub type Wupp6R = crate::BitReader;
#[doc = "Field `WUPP6` writer - Wakeup pin polarity bit for PI11"]
pub type Wupp6W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Clear Wakeup Pin flag for PA0"]
    #[inline(always)]
    pub fn cwupf1(&self) -> Cwupf1R {
        Cwupf1R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Clear Wakeup Pin flag for PA2"]
    #[inline(always)]
    pub fn cwupf2(&self) -> Cwupf2R {
        Cwupf2R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Clear Wakeup Pin flag for PC1"]
    #[inline(always)]
    pub fn cwupf3(&self) -> Cwupf3R {
        Cwupf3R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Clear Wakeup Pin flag for PC13"]
    #[inline(always)]
    pub fn cwupf4(&self) -> Cwupf4R {
        Cwupf4R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Clear Wakeup Pin flag for PI8"]
    #[inline(always)]
    pub fn cwupf5(&self) -> Cwupf5R {
        Cwupf5R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Clear Wakeup Pin flag for PI11"]
    #[inline(always)]
    pub fn cwupf6(&self) -> Cwupf6R {
        Cwupf6R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 8 - Wakeup pin polarity bit for PA0"]
    #[inline(always)]
    pub fn wupp1(&self) -> Wupp1R {
        Wupp1R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Wakeup pin polarity bit for PA2"]
    #[inline(always)]
    pub fn wupp2(&self) -> Wupp2R {
        Wupp2R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Wakeup pin polarity bit for PC1"]
    #[inline(always)]
    pub fn wupp3(&self) -> Wupp3R {
        Wupp3R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Wakeup pin polarity bit for PC13"]
    #[inline(always)]
    pub fn wupp4(&self) -> Wupp4R {
        Wupp4R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Wakeup pin polarity bit for PI8"]
    #[inline(always)]
    pub fn wupp5(&self) -> Wupp5R {
        Wupp5R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Wakeup pin polarity bit for PI11"]
    #[inline(always)]
    pub fn wupp6(&self) -> Wupp6R {
        Wupp6R::new(((self.bits >> 13) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Clear Wakeup Pin flag for PA0"]
    #[inline(always)]
    #[must_use]
    pub fn cwupf1(&mut self) -> Cwupf1W<Cr2Spec> {
        Cwupf1W::new(self, 0)
    }
    #[doc = "Bit 1 - Clear Wakeup Pin flag for PA2"]
    #[inline(always)]
    #[must_use]
    pub fn cwupf2(&mut self) -> Cwupf2W<Cr2Spec> {
        Cwupf2W::new(self, 1)
    }
    #[doc = "Bit 2 - Clear Wakeup Pin flag for PC1"]
    #[inline(always)]
    #[must_use]
    pub fn cwupf3(&mut self) -> Cwupf3W<Cr2Spec> {
        Cwupf3W::new(self, 2)
    }
    #[doc = "Bit 3 - Clear Wakeup Pin flag for PC13"]
    #[inline(always)]
    #[must_use]
    pub fn cwupf4(&mut self) -> Cwupf4W<Cr2Spec> {
        Cwupf4W::new(self, 3)
    }
    #[doc = "Bit 4 - Clear Wakeup Pin flag for PI8"]
    #[inline(always)]
    #[must_use]
    pub fn cwupf5(&mut self) -> Cwupf5W<Cr2Spec> {
        Cwupf5W::new(self, 4)
    }
    #[doc = "Bit 5 - Clear Wakeup Pin flag for PI11"]
    #[inline(always)]
    #[must_use]
    pub fn cwupf6(&mut self) -> Cwupf6W<Cr2Spec> {
        Cwupf6W::new(self, 5)
    }
    #[doc = "Bit 8 - Wakeup pin polarity bit for PA0"]
    #[inline(always)]
    #[must_use]
    pub fn wupp1(&mut self) -> Wupp1W<Cr2Spec> {
        Wupp1W::new(self, 8)
    }
    #[doc = "Bit 9 - Wakeup pin polarity bit for PA2"]
    #[inline(always)]
    #[must_use]
    pub fn wupp2(&mut self) -> Wupp2W<Cr2Spec> {
        Wupp2W::new(self, 9)
    }
    #[doc = "Bit 10 - Wakeup pin polarity bit for PC1"]
    #[inline(always)]
    #[must_use]
    pub fn wupp3(&mut self) -> Wupp3W<Cr2Spec> {
        Wupp3W::new(self, 10)
    }
    #[doc = "Bit 11 - Wakeup pin polarity bit for PC13"]
    #[inline(always)]
    #[must_use]
    pub fn wupp4(&mut self) -> Wupp4W<Cr2Spec> {
        Wupp4W::new(self, 11)
    }
    #[doc = "Bit 12 - Wakeup pin polarity bit for PI8"]
    #[inline(always)]
    #[must_use]
    pub fn wupp5(&mut self) -> Wupp5W<Cr2Spec> {
        Wupp5W::new(self, 12)
    }
    #[doc = "Bit 13 - Wakeup pin polarity bit for PI11"]
    #[inline(always)]
    #[must_use]
    pub fn wupp6(&mut self) -> Wupp6W<Cr2Spec> {
        Wupp6W::new(self, 13)
    }
}
#[doc = "power control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Cr2Spec;
impl crate::RegisterSpec for Cr2Spec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`cr2::R`](R) reader structure"]
impl crate::Readable for Cr2Spec {}
#[doc = "`write(|w| ..)` method takes [`cr2::W`](W) writer structure"]
impl crate::Writable for Cr2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CR2 to value 0"]
impl crate::Resettable for Cr2Spec {
    const RESET_VALUE: u32 = 0;
}
