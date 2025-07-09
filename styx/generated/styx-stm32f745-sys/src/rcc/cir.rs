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
#[doc = "Register `CIR` reader"]
pub type R = crate::R<CirSpec>;
#[doc = "Register `CIR` writer"]
pub type W = crate::W<CirSpec>;
#[doc = "Field `LSIRDYF` reader - LSI ready interrupt flag"]
pub type LsirdyfR = crate::BitReader;
#[doc = "Field `LSIRDYF` writer - LSI ready interrupt flag"]
pub type LsirdyfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LSERDYF` reader - LSE ready interrupt flag"]
pub type LserdyfR = crate::BitReader;
#[doc = "Field `LSERDYF` writer - LSE ready interrupt flag"]
pub type LserdyfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HSIRDYF` reader - HSI ready interrupt flag"]
pub type HsirdyfR = crate::BitReader;
#[doc = "Field `HSIRDYF` writer - HSI ready interrupt flag"]
pub type HsirdyfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HSERDYF` reader - HSE ready interrupt flag"]
pub type HserdyfR = crate::BitReader;
#[doc = "Field `HSERDYF` writer - HSE ready interrupt flag"]
pub type HserdyfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLRDYF` reader - Main PLL (PLL) ready interrupt flag"]
pub type PllrdyfR = crate::BitReader;
#[doc = "Field `PLLRDYF` writer - Main PLL (PLL) ready interrupt flag"]
pub type PllrdyfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLI2SRDYF` reader - PLLI2S ready interrupt flag"]
pub type Plli2srdyfR = crate::BitReader;
#[doc = "Field `PLLI2SRDYF` writer - PLLI2S ready interrupt flag"]
pub type Plli2srdyfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLSAIRDYF` reader - PLLSAI ready interrupt flag"]
pub type PllsairdyfR = crate::BitReader;
#[doc = "Field `PLLSAIRDYF` writer - PLLSAI ready interrupt flag"]
pub type PllsairdyfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CSSF` reader - Clock security system interrupt flag"]
pub type CssfR = crate::BitReader;
#[doc = "Field `CSSF` writer - Clock security system interrupt flag"]
pub type CssfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LSIRDYIE` reader - LSI ready interrupt enable"]
pub type LsirdyieR = crate::BitReader;
#[doc = "Field `LSIRDYIE` writer - LSI ready interrupt enable"]
pub type LsirdyieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LSERDYIE` reader - LSE ready interrupt enable"]
pub type LserdyieR = crate::BitReader;
#[doc = "Field `LSERDYIE` writer - LSE ready interrupt enable"]
pub type LserdyieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HSIRDYIE` reader - HSI ready interrupt enable"]
pub type HsirdyieR = crate::BitReader;
#[doc = "Field `HSIRDYIE` writer - HSI ready interrupt enable"]
pub type HsirdyieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HSERDYIE` reader - HSE ready interrupt enable"]
pub type HserdyieR = crate::BitReader;
#[doc = "Field `HSERDYIE` writer - HSE ready interrupt enable"]
pub type HserdyieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLRDYIE` reader - Main PLL (PLL) ready interrupt enable"]
pub type PllrdyieR = crate::BitReader;
#[doc = "Field `PLLRDYIE` writer - Main PLL (PLL) ready interrupt enable"]
pub type PllrdyieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLI2SRDYIE` reader - PLLI2S ready interrupt enable"]
pub type Plli2srdyieR = crate::BitReader;
#[doc = "Field `PLLI2SRDYIE` writer - PLLI2S ready interrupt enable"]
pub type Plli2srdyieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLSAIRDYIE` reader - PLLSAI Ready Interrupt Enable"]
pub type PllsairdyieR = crate::BitReader;
#[doc = "Field `PLLSAIRDYIE` writer - PLLSAI Ready Interrupt Enable"]
pub type PllsairdyieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LSIRDYC` reader - LSI ready interrupt clear"]
pub type LsirdycR = crate::BitReader;
#[doc = "Field `LSIRDYC` writer - LSI ready interrupt clear"]
pub type LsirdycW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LSERDYC` reader - LSE ready interrupt clear"]
pub type LserdycR = crate::BitReader;
#[doc = "Field `LSERDYC` writer - LSE ready interrupt clear"]
pub type LserdycW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HSIRDYC` reader - HSI ready interrupt clear"]
pub type HsirdycR = crate::BitReader;
#[doc = "Field `HSIRDYC` writer - HSI ready interrupt clear"]
pub type HsirdycW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HSERDYC` reader - HSE ready interrupt clear"]
pub type HserdycR = crate::BitReader;
#[doc = "Field `HSERDYC` writer - HSE ready interrupt clear"]
pub type HserdycW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLRDYC` reader - Main PLL(PLL) ready interrupt clear"]
pub type PllrdycR = crate::BitReader;
#[doc = "Field `PLLRDYC` writer - Main PLL(PLL) ready interrupt clear"]
pub type PllrdycW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLI2SRDYC` reader - PLLI2S ready interrupt clear"]
pub type Plli2srdycR = crate::BitReader;
#[doc = "Field `PLLI2SRDYC` writer - PLLI2S ready interrupt clear"]
pub type Plli2srdycW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLLSAIRDYC` reader - PLLSAI Ready Interrupt Clear"]
pub type PllsairdycR = crate::BitReader;
#[doc = "Field `PLLSAIRDYC` writer - PLLSAI Ready Interrupt Clear"]
pub type PllsairdycW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CSSC` reader - Clock security system interrupt clear"]
pub type CsscR = crate::BitReader;
#[doc = "Field `CSSC` writer - Clock security system interrupt clear"]
pub type CsscW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - LSI ready interrupt flag"]
    #[inline(always)]
    pub fn lsirdyf(&self) -> LsirdyfR {
        LsirdyfR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - LSE ready interrupt flag"]
    #[inline(always)]
    pub fn lserdyf(&self) -> LserdyfR {
        LserdyfR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - HSI ready interrupt flag"]
    #[inline(always)]
    pub fn hsirdyf(&self) -> HsirdyfR {
        HsirdyfR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - HSE ready interrupt flag"]
    #[inline(always)]
    pub fn hserdyf(&self) -> HserdyfR {
        HserdyfR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Main PLL (PLL) ready interrupt flag"]
    #[inline(always)]
    pub fn pllrdyf(&self) -> PllrdyfR {
        PllrdyfR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - PLLI2S ready interrupt flag"]
    #[inline(always)]
    pub fn plli2srdyf(&self) -> Plli2srdyfR {
        Plli2srdyfR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - PLLSAI ready interrupt flag"]
    #[inline(always)]
    pub fn pllsairdyf(&self) -> PllsairdyfR {
        PllsairdyfR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 7 - Clock security system interrupt flag"]
    #[inline(always)]
    pub fn cssf(&self) -> CssfR {
        CssfR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bit 8 - LSI ready interrupt enable"]
    #[inline(always)]
    pub fn lsirdyie(&self) -> LsirdyieR {
        LsirdyieR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - LSE ready interrupt enable"]
    #[inline(always)]
    pub fn lserdyie(&self) -> LserdyieR {
        LserdyieR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - HSI ready interrupt enable"]
    #[inline(always)]
    pub fn hsirdyie(&self) -> HsirdyieR {
        HsirdyieR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - HSE ready interrupt enable"]
    #[inline(always)]
    pub fn hserdyie(&self) -> HserdyieR {
        HserdyieR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Main PLL (PLL) ready interrupt enable"]
    #[inline(always)]
    pub fn pllrdyie(&self) -> PllrdyieR {
        PllrdyieR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - PLLI2S ready interrupt enable"]
    #[inline(always)]
    pub fn plli2srdyie(&self) -> Plli2srdyieR {
        Plli2srdyieR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - PLLSAI Ready Interrupt Enable"]
    #[inline(always)]
    pub fn pllsairdyie(&self) -> PllsairdyieR {
        PllsairdyieR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 16 - LSI ready interrupt clear"]
    #[inline(always)]
    pub fn lsirdyc(&self) -> LsirdycR {
        LsirdycR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - LSE ready interrupt clear"]
    #[inline(always)]
    pub fn lserdyc(&self) -> LserdycR {
        LserdycR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - HSI ready interrupt clear"]
    #[inline(always)]
    pub fn hsirdyc(&self) -> HsirdycR {
        HsirdycR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - HSE ready interrupt clear"]
    #[inline(always)]
    pub fn hserdyc(&self) -> HserdycR {
        HserdycR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Main PLL(PLL) ready interrupt clear"]
    #[inline(always)]
    pub fn pllrdyc(&self) -> PllrdycR {
        PllrdycR::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - PLLI2S ready interrupt clear"]
    #[inline(always)]
    pub fn plli2srdyc(&self) -> Plli2srdycR {
        Plli2srdycR::new(((self.bits >> 21) & 1) != 0)
    }
    #[doc = "Bit 22 - PLLSAI Ready Interrupt Clear"]
    #[inline(always)]
    pub fn pllsairdyc(&self) -> PllsairdycR {
        PllsairdycR::new(((self.bits >> 22) & 1) != 0)
    }
    #[doc = "Bit 23 - Clock security system interrupt clear"]
    #[inline(always)]
    pub fn cssc(&self) -> CsscR {
        CsscR::new(((self.bits >> 23) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - LSI ready interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn lsirdyf(&mut self) -> LsirdyfW<CirSpec> {
        LsirdyfW::new(self, 0)
    }
    #[doc = "Bit 1 - LSE ready interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn lserdyf(&mut self) -> LserdyfW<CirSpec> {
        LserdyfW::new(self, 1)
    }
    #[doc = "Bit 2 - HSI ready interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn hsirdyf(&mut self) -> HsirdyfW<CirSpec> {
        HsirdyfW::new(self, 2)
    }
    #[doc = "Bit 3 - HSE ready interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn hserdyf(&mut self) -> HserdyfW<CirSpec> {
        HserdyfW::new(self, 3)
    }
    #[doc = "Bit 4 - Main PLL (PLL) ready interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn pllrdyf(&mut self) -> PllrdyfW<CirSpec> {
        PllrdyfW::new(self, 4)
    }
    #[doc = "Bit 5 - PLLI2S ready interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn plli2srdyf(&mut self) -> Plli2srdyfW<CirSpec> {
        Plli2srdyfW::new(self, 5)
    }
    #[doc = "Bit 6 - PLLSAI ready interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn pllsairdyf(&mut self) -> PllsairdyfW<CirSpec> {
        PllsairdyfW::new(self, 6)
    }
    #[doc = "Bit 7 - Clock security system interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn cssf(&mut self) -> CssfW<CirSpec> {
        CssfW::new(self, 7)
    }
    #[doc = "Bit 8 - LSI ready interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn lsirdyie(&mut self) -> LsirdyieW<CirSpec> {
        LsirdyieW::new(self, 8)
    }
    #[doc = "Bit 9 - LSE ready interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn lserdyie(&mut self) -> LserdyieW<CirSpec> {
        LserdyieW::new(self, 9)
    }
    #[doc = "Bit 10 - HSI ready interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn hsirdyie(&mut self) -> HsirdyieW<CirSpec> {
        HsirdyieW::new(self, 10)
    }
    #[doc = "Bit 11 - HSE ready interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn hserdyie(&mut self) -> HserdyieW<CirSpec> {
        HserdyieW::new(self, 11)
    }
    #[doc = "Bit 12 - Main PLL (PLL) ready interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn pllrdyie(&mut self) -> PllrdyieW<CirSpec> {
        PllrdyieW::new(self, 12)
    }
    #[doc = "Bit 13 - PLLI2S ready interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn plli2srdyie(&mut self) -> Plli2srdyieW<CirSpec> {
        Plli2srdyieW::new(self, 13)
    }
    #[doc = "Bit 14 - PLLSAI Ready Interrupt Enable"]
    #[inline(always)]
    #[must_use]
    pub fn pllsairdyie(&mut self) -> PllsairdyieW<CirSpec> {
        PllsairdyieW::new(self, 14)
    }
    #[doc = "Bit 16 - LSI ready interrupt clear"]
    #[inline(always)]
    #[must_use]
    pub fn lsirdyc(&mut self) -> LsirdycW<CirSpec> {
        LsirdycW::new(self, 16)
    }
    #[doc = "Bit 17 - LSE ready interrupt clear"]
    #[inline(always)]
    #[must_use]
    pub fn lserdyc(&mut self) -> LserdycW<CirSpec> {
        LserdycW::new(self, 17)
    }
    #[doc = "Bit 18 - HSI ready interrupt clear"]
    #[inline(always)]
    #[must_use]
    pub fn hsirdyc(&mut self) -> HsirdycW<CirSpec> {
        HsirdycW::new(self, 18)
    }
    #[doc = "Bit 19 - HSE ready interrupt clear"]
    #[inline(always)]
    #[must_use]
    pub fn hserdyc(&mut self) -> HserdycW<CirSpec> {
        HserdycW::new(self, 19)
    }
    #[doc = "Bit 20 - Main PLL(PLL) ready interrupt clear"]
    #[inline(always)]
    #[must_use]
    pub fn pllrdyc(&mut self) -> PllrdycW<CirSpec> {
        PllrdycW::new(self, 20)
    }
    #[doc = "Bit 21 - PLLI2S ready interrupt clear"]
    #[inline(always)]
    #[must_use]
    pub fn plli2srdyc(&mut self) -> Plli2srdycW<CirSpec> {
        Plli2srdycW::new(self, 21)
    }
    #[doc = "Bit 22 - PLLSAI Ready Interrupt Clear"]
    #[inline(always)]
    #[must_use]
    pub fn pllsairdyc(&mut self) -> PllsairdycW<CirSpec> {
        PllsairdycW::new(self, 22)
    }
    #[doc = "Bit 23 - Clock security system interrupt clear"]
    #[inline(always)]
    #[must_use]
    pub fn cssc(&mut self) -> CsscW<CirSpec> {
        CsscW::new(self, 23)
    }
}
#[doc = "clock interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cir::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cir::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CirSpec;
impl crate::RegisterSpec for CirSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`cir::R`](R) reader structure"]
impl crate::Readable for CirSpec {}
#[doc = "`write(|w| ..)` method takes [`cir::W`](W) writer structure"]
impl crate::Writable for CirSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CIR to value 0"]
impl crate::Resettable for CirSpec {
    const RESET_VALUE: u32 = 0;
}
