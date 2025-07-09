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
#[doc = "Register `DKCFGR1` reader"]
pub type R = crate::R<Dkcfgr1Spec>;
#[doc = "Register `DKCFGR1` writer"]
pub type W = crate::W<Dkcfgr1Spec>;
#[doc = "Field `PLLI2SDIV` reader - PLLI2S division factor for SAI1 clock"]
pub type Plli2sdivR = crate::FieldReader;
#[doc = "Field `PLLI2SDIV` writer - PLLI2S division factor for SAI1 clock"]
pub type Plli2sdivW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `PLLSAIDIVQ` reader - PLLSAI division factor for SAI1 clock"]
pub type PllsaidivqR = crate::FieldReader;
#[doc = "Field `PLLSAIDIVQ` writer - PLLSAI division factor for SAI1 clock"]
pub type PllsaidivqW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `PLLSAIDIVR` reader - division factor for LCD_CLK"]
pub type PllsaidivrR = crate::FieldReader;
#[doc = "Field `PLLSAIDIVR` writer - division factor for LCD_CLK"]
pub type PllsaidivrW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `SAI1SEL` reader - SAI1 clock source selection"]
pub type Sai1selR = crate::FieldReader;
#[doc = "Field `SAI1SEL` writer - SAI1 clock source selection"]
pub type Sai1selW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `SAI2SEL` reader - SAI2 clock source selection"]
pub type Sai2selR = crate::FieldReader;
#[doc = "Field `SAI2SEL` writer - SAI2 clock source selection"]
pub type Sai2selW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `TIMPRE` reader - Timers clocks prescalers selection"]
pub type TimpreR = crate::BitReader;
#[doc = "Field `TIMPRE` writer - Timers clocks prescalers selection"]
pub type TimpreW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:4 - PLLI2S division factor for SAI1 clock"]
    #[inline(always)]
    pub fn plli2sdiv(&self) -> Plli2sdivR {
        Plli2sdivR::new((self.bits & 0x1f) as u8)
    }
    #[doc = "Bits 8:12 - PLLSAI division factor for SAI1 clock"]
    #[inline(always)]
    pub fn pllsaidivq(&self) -> PllsaidivqR {
        PllsaidivqR::new(((self.bits >> 8) & 0x1f) as u8)
    }
    #[doc = "Bits 16:17 - division factor for LCD_CLK"]
    #[inline(always)]
    pub fn pllsaidivr(&self) -> PllsaidivrR {
        PllsaidivrR::new(((self.bits >> 16) & 3) as u8)
    }
    #[doc = "Bits 20:21 - SAI1 clock source selection"]
    #[inline(always)]
    pub fn sai1sel(&self) -> Sai1selR {
        Sai1selR::new(((self.bits >> 20) & 3) as u8)
    }
    #[doc = "Bits 22:23 - SAI2 clock source selection"]
    #[inline(always)]
    pub fn sai2sel(&self) -> Sai2selR {
        Sai2selR::new(((self.bits >> 22) & 3) as u8)
    }
    #[doc = "Bit 24 - Timers clocks prescalers selection"]
    #[inline(always)]
    pub fn timpre(&self) -> TimpreR {
        TimpreR::new(((self.bits >> 24) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:4 - PLLI2S division factor for SAI1 clock"]
    #[inline(always)]
    #[must_use]
    pub fn plli2sdiv(&mut self) -> Plli2sdivW<Dkcfgr1Spec> {
        Plli2sdivW::new(self, 0)
    }
    #[doc = "Bits 8:12 - PLLSAI division factor for SAI1 clock"]
    #[inline(always)]
    #[must_use]
    pub fn pllsaidivq(&mut self) -> PllsaidivqW<Dkcfgr1Spec> {
        PllsaidivqW::new(self, 8)
    }
    #[doc = "Bits 16:17 - division factor for LCD_CLK"]
    #[inline(always)]
    #[must_use]
    pub fn pllsaidivr(&mut self) -> PllsaidivrW<Dkcfgr1Spec> {
        PllsaidivrW::new(self, 16)
    }
    #[doc = "Bits 20:21 - SAI1 clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn sai1sel(&mut self) -> Sai1selW<Dkcfgr1Spec> {
        Sai1selW::new(self, 20)
    }
    #[doc = "Bits 22:23 - SAI2 clock source selection"]
    #[inline(always)]
    #[must_use]
    pub fn sai2sel(&mut self) -> Sai2selW<Dkcfgr1Spec> {
        Sai2selW::new(self, 22)
    }
    #[doc = "Bit 24 - Timers clocks prescalers selection"]
    #[inline(always)]
    #[must_use]
    pub fn timpre(&mut self) -> TimpreW<Dkcfgr1Spec> {
        TimpreW::new(self, 24)
    }
}
#[doc = "dedicated clocks configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dkcfgr1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dkcfgr1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Dkcfgr1Spec;
impl crate::RegisterSpec for Dkcfgr1Spec {
    type Ux = u32;
    const OFFSET: u64 = 140u64;
}
#[doc = "`read()` method returns [`dkcfgr1::R`](R) reader structure"]
impl crate::Readable for Dkcfgr1Spec {}
#[doc = "`write(|w| ..)` method takes [`dkcfgr1::W`](W) writer structure"]
impl crate::Writable for Dkcfgr1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DKCFGR1 to value 0x2000_3000"]
impl crate::Resettable for Dkcfgr1Spec {
    const RESET_VALUE: u32 = 0x2000_3000;
}
