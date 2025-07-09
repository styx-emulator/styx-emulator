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
#[doc = "Register `CR` reader"]
pub type R = crate::R<CrSpec>;
#[doc = "Register `CR` writer"]
pub type W = crate::W<CrSpec>;
#[doc = "Field `HSION` reader - Internal high-speed clock enable"]
pub type HsionR = crate::BitReader;
#[doc = "Field `HSION` writer - Internal high-speed clock enable"]
pub type HsionW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HSIRDY` reader - Internal high-speed clock ready flag"]
pub type HsirdyR = crate::BitReader;
#[doc = "Field `HSIRDY` writer - Internal high-speed clock ready flag"]
pub type HsirdyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HSITRIM` reader - Internal high-speed clock trimming"]
pub type HsitrimR = crate::FieldReader;
#[doc = "Field `HSITRIM` writer - Internal high-speed clock trimming"]
pub type HsitrimW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `HSICAL` reader - Internal high-speed clock calibration"]
pub type HsicalR = crate::FieldReader;
#[doc = "Field `HSICAL` writer - Internal high-speed clock calibration"]
pub type HsicalW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `HSEON` reader - HSE clock enable"]
pub type HseonR = crate::BitReader;
#[doc = "Field `HSEON` writer - HSE clock enable"]
pub type HseonW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HSERDY` reader - HSE clock ready flag"]
pub type HserdyR = crate::BitReader;
#[doc = "Field `HSERDY` writer - HSE clock ready flag"]
pub type HserdyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HSEBYP` reader - HSE clock bypass"]
pub type HsebypR = crate::BitReader;
#[doc = "Field `HSEBYP` writer - HSE clock bypass"]
pub type HsebypW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CSSON` reader - Clock security system enable"]
pub type CssonR = crate::BitReader;
#[doc = "Field `CSSON` writer - Clock security system enable"]
pub type CssonW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLON` reader - Main PLL (PLL) enable"]
pub type PllonR = crate::BitReader;
#[doc = "Field `PLLON` writer - Main PLL (PLL) enable"]
pub type PllonW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLRDY` reader - Main PLL (PLL) clock ready flag"]
pub type PllrdyR = crate::BitReader;
#[doc = "Field `PLLRDY` writer - Main PLL (PLL) clock ready flag"]
pub type PllrdyW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLI2SON` reader - PLLI2S enable"]
pub type Plli2sonR = crate::BitReader;
#[doc = "Field `PLLI2SON` writer - PLLI2S enable"]
pub type Plli2sonW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLI2SRDY` reader - PLLI2S clock ready flag"]
pub type Plli2srdyR = crate::BitReader;
#[doc = "Field `PLLI2SRDY` writer - PLLI2S clock ready flag"]
pub type Plli2srdyW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Internal high-speed clock enable"]
    #[inline(always)]
    pub fn hsion(&self) -> HsionR {
        HsionR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Internal high-speed clock ready flag"]
    #[inline(always)]
    pub fn hsirdy(&self) -> HsirdyR {
        HsirdyR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bits 3:7 - Internal high-speed clock trimming"]
    #[inline(always)]
    pub fn hsitrim(&self) -> HsitrimR {
        HsitrimR::new(((self.bits >> 3) & 0x1f) as u8)
    }
    #[doc = "Bits 8:15 - Internal high-speed clock calibration"]
    #[inline(always)]
    pub fn hsical(&self) -> HsicalR {
        HsicalR::new(((self.bits >> 8) & 0xff) as u8)
    }
    #[doc = "Bit 16 - HSE clock enable"]
    #[inline(always)]
    pub fn hseon(&self) -> HseonR {
        HseonR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - HSE clock ready flag"]
    #[inline(always)]
    pub fn hserdy(&self) -> HserdyR {
        HserdyR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - HSE clock bypass"]
    #[inline(always)]
    pub fn hsebyp(&self) -> HsebypR {
        HsebypR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Clock security system enable"]
    #[inline(always)]
    pub fn csson(&self) -> CssonR {
        CssonR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 24 - Main PLL (PLL) enable"]
    #[inline(always)]
    pub fn pllon(&self) -> PllonR {
        PllonR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - Main PLL (PLL) clock ready flag"]
    #[inline(always)]
    pub fn pllrdy(&self) -> PllrdyR {
        PllrdyR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - PLLI2S enable"]
    #[inline(always)]
    pub fn plli2son(&self) -> Plli2sonR {
        Plli2sonR::new(((self.bits >> 26) & 1) != 0)
    }
    #[doc = "Bit 27 - PLLI2S clock ready flag"]
    #[inline(always)]
    pub fn plli2srdy(&self) -> Plli2srdyR {
        Plli2srdyR::new(((self.bits >> 27) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Internal high-speed clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn hsion(&mut self) -> HsionW<CrSpec> {
        HsionW::new(self, 0)
    }
    #[doc = "Bit 1 - Internal high-speed clock ready flag"]
    #[inline(always)]
    #[must_use]
    pub fn hsirdy(&mut self) -> HsirdyW<CrSpec> {
        HsirdyW::new(self, 1)
    }
    #[doc = "Bits 3:7 - Internal high-speed clock trimming"]
    #[inline(always)]
    #[must_use]
    pub fn hsitrim(&mut self) -> HsitrimW<CrSpec> {
        HsitrimW::new(self, 3)
    }
    #[doc = "Bits 8:15 - Internal high-speed clock calibration"]
    #[inline(always)]
    #[must_use]
    pub fn hsical(&mut self) -> HsicalW<CrSpec> {
        HsicalW::new(self, 8)
    }
    #[doc = "Bit 16 - HSE clock enable"]
    #[inline(always)]
    #[must_use]
    pub fn hseon(&mut self) -> HseonW<CrSpec> {
        HseonW::new(self, 16)
    }
    #[doc = "Bit 17 - HSE clock ready flag"]
    #[inline(always)]
    #[must_use]
    pub fn hserdy(&mut self) -> HserdyW<CrSpec> {
        HserdyW::new(self, 17)
    }
    #[doc = "Bit 18 - HSE clock bypass"]
    #[inline(always)]
    #[must_use]
    pub fn hsebyp(&mut self) -> HsebypW<CrSpec> {
        HsebypW::new(self, 18)
    }
    #[doc = "Bit 19 - Clock security system enable"]
    #[inline(always)]
    #[must_use]
    pub fn csson(&mut self) -> CssonW<CrSpec> {
        CssonW::new(self, 19)
    }
    #[doc = "Bit 24 - Main PLL (PLL) enable"]
    #[inline(always)]
    #[must_use]
    pub fn pllon(&mut self) -> PllonW<CrSpec> {
        PllonW::new(self, 24)
    }
    #[doc = "Bit 25 - Main PLL (PLL) clock ready flag"]
    #[inline(always)]
    #[must_use]
    pub fn pllrdy(&mut self) -> PllrdyW<CrSpec> {
        PllrdyW::new(self, 25)
    }
    #[doc = "Bit 26 - PLLI2S enable"]
    #[inline(always)]
    #[must_use]
    pub fn plli2son(&mut self) -> Plli2sonW<CrSpec> {
        Plli2sonW::new(self, 26)
    }
    #[doc = "Bit 27 - PLLI2S clock ready flag"]
    #[inline(always)]
    #[must_use]
    pub fn plli2srdy(&mut self) -> Plli2srdyW<CrSpec> {
        Plli2srdyW::new(self, 27)
    }
}
#[doc = "clock control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CrSpec;
impl crate::RegisterSpec for CrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`cr::R`](R) reader structure"]
impl crate::Readable for CrSpec {}
#[doc = "`write(|w| ..)` method takes [`cr::W`](W) writer structure"]
impl crate::Writable for CrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CR to value 0x83"]
impl crate::Resettable for CrSpec {
    const RESET_VALUE: u32 = 0x83;
}
