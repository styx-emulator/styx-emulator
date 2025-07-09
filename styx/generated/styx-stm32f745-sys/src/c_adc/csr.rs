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
#[doc = "Register `CSR` reader"]
pub type R = crate::R<CsrSpec>;
#[doc = "Register `CSR` writer"]
pub type W = crate::W<CsrSpec>;
#[doc = "Field `AWD1` reader - Analog watchdog flag of ADC 1"]
pub type Awd1R = crate::BitReader;
#[doc = "Field `AWD1` writer - Analog watchdog flag of ADC 1"]
pub type Awd1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EOC1` reader - End of conversion of ADC 1"]
pub type Eoc1R = crate::BitReader;
#[doc = "Field `EOC1` writer - End of conversion of ADC 1"]
pub type Eoc1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `JEOC1` reader - Injected channel end of conversion of ADC 1"]
pub type Jeoc1R = crate::BitReader;
#[doc = "Field `JEOC1` writer - Injected channel end of conversion of ADC 1"]
pub type Jeoc1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `JSTRT1` reader - Injected channel Start flag of ADC 1"]
pub type Jstrt1R = crate::BitReader;
#[doc = "Field `JSTRT1` writer - Injected channel Start flag of ADC 1"]
pub type Jstrt1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `STRT1` reader - Regular channel Start flag of ADC 1"]
pub type Strt1R = crate::BitReader;
#[doc = "Field `STRT1` writer - Regular channel Start flag of ADC 1"]
pub type Strt1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OVR1` reader - Overrun flag of ADC 1"]
pub type Ovr1R = crate::BitReader;
#[doc = "Field `OVR1` writer - Overrun flag of ADC 1"]
pub type Ovr1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AWD2` reader - Analog watchdog flag of ADC 2"]
pub type Awd2R = crate::BitReader;
#[doc = "Field `AWD2` writer - Analog watchdog flag of ADC 2"]
pub type Awd2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EOC2` reader - End of conversion of ADC 2"]
pub type Eoc2R = crate::BitReader;
#[doc = "Field `EOC2` writer - End of conversion of ADC 2"]
pub type Eoc2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `JEOC2` reader - Injected channel end of conversion of ADC 2"]
pub type Jeoc2R = crate::BitReader;
#[doc = "Field `JEOC2` writer - Injected channel end of conversion of ADC 2"]
pub type Jeoc2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `JSTRT2` reader - Injected channel Start flag of ADC 2"]
pub type Jstrt2R = crate::BitReader;
#[doc = "Field `JSTRT2` writer - Injected channel Start flag of ADC 2"]
pub type Jstrt2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `STRT2` reader - Regular channel Start flag of ADC 2"]
pub type Strt2R = crate::BitReader;
#[doc = "Field `STRT2` writer - Regular channel Start flag of ADC 2"]
pub type Strt2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OVR2` reader - Overrun flag of ADC 2"]
pub type Ovr2R = crate::BitReader;
#[doc = "Field `OVR2` writer - Overrun flag of ADC 2"]
pub type Ovr2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AWD3` reader - Analog watchdog flag of ADC 3"]
pub type Awd3R = crate::BitReader;
#[doc = "Field `AWD3` writer - Analog watchdog flag of ADC 3"]
pub type Awd3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EOC3` reader - End of conversion of ADC 3"]
pub type Eoc3R = crate::BitReader;
#[doc = "Field `EOC3` writer - End of conversion of ADC 3"]
pub type Eoc3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `JEOC3` reader - Injected channel end of conversion of ADC 3"]
pub type Jeoc3R = crate::BitReader;
#[doc = "Field `JEOC3` writer - Injected channel end of conversion of ADC 3"]
pub type Jeoc3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `JSTRT3` reader - Injected channel Start flag of ADC 3"]
pub type Jstrt3R = crate::BitReader;
#[doc = "Field `JSTRT3` writer - Injected channel Start flag of ADC 3"]
pub type Jstrt3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `STRT3` reader - Regular channel Start flag of ADC 3"]
pub type Strt3R = crate::BitReader;
#[doc = "Field `STRT3` writer - Regular channel Start flag of ADC 3"]
pub type Strt3W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OVR3` reader - Overrun flag of ADC3"]
pub type Ovr3R = crate::BitReader;
#[doc = "Field `OVR3` writer - Overrun flag of ADC3"]
pub type Ovr3W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Analog watchdog flag of ADC 1"]
    #[inline(always)]
    pub fn awd1(&self) -> Awd1R {
        Awd1R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - End of conversion of ADC 1"]
    #[inline(always)]
    pub fn eoc1(&self) -> Eoc1R {
        Eoc1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Injected channel end of conversion of ADC 1"]
    #[inline(always)]
    pub fn jeoc1(&self) -> Jeoc1R {
        Jeoc1R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Injected channel Start flag of ADC 1"]
    #[inline(always)]
    pub fn jstrt1(&self) -> Jstrt1R {
        Jstrt1R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Regular channel Start flag of ADC 1"]
    #[inline(always)]
    pub fn strt1(&self) -> Strt1R {
        Strt1R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Overrun flag of ADC 1"]
    #[inline(always)]
    pub fn ovr1(&self) -> Ovr1R {
        Ovr1R::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 8 - Analog watchdog flag of ADC 2"]
    #[inline(always)]
    pub fn awd2(&self) -> Awd2R {
        Awd2R::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - End of conversion of ADC 2"]
    #[inline(always)]
    pub fn eoc2(&self) -> Eoc2R {
        Eoc2R::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Injected channel end of conversion of ADC 2"]
    #[inline(always)]
    pub fn jeoc2(&self) -> Jeoc2R {
        Jeoc2R::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Injected channel Start flag of ADC 2"]
    #[inline(always)]
    pub fn jstrt2(&self) -> Jstrt2R {
        Jstrt2R::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Regular channel Start flag of ADC 2"]
    #[inline(always)]
    pub fn strt2(&self) -> Strt2R {
        Strt2R::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Overrun flag of ADC 2"]
    #[inline(always)]
    pub fn ovr2(&self) -> Ovr2R {
        Ovr2R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 16 - Analog watchdog flag of ADC 3"]
    #[inline(always)]
    pub fn awd3(&self) -> Awd3R {
        Awd3R::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - End of conversion of ADC 3"]
    #[inline(always)]
    pub fn eoc3(&self) -> Eoc3R {
        Eoc3R::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - Injected channel end of conversion of ADC 3"]
    #[inline(always)]
    pub fn jeoc3(&self) -> Jeoc3R {
        Jeoc3R::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Injected channel Start flag of ADC 3"]
    #[inline(always)]
    pub fn jstrt3(&self) -> Jstrt3R {
        Jstrt3R::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - Regular channel Start flag of ADC 3"]
    #[inline(always)]
    pub fn strt3(&self) -> Strt3R {
        Strt3R::new(((self.bits >> 20) & 1) != 0)
    }
    #[doc = "Bit 21 - Overrun flag of ADC3"]
    #[inline(always)]
    pub fn ovr3(&self) -> Ovr3R {
        Ovr3R::new(((self.bits >> 21) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Analog watchdog flag of ADC 1"]
    #[inline(always)]
    #[must_use]
    pub fn awd1(&mut self) -> Awd1W<CsrSpec> {
        Awd1W::new(self, 0)
    }
    #[doc = "Bit 1 - End of conversion of ADC 1"]
    #[inline(always)]
    #[must_use]
    pub fn eoc1(&mut self) -> Eoc1W<CsrSpec> {
        Eoc1W::new(self, 1)
    }
    #[doc = "Bit 2 - Injected channel end of conversion of ADC 1"]
    #[inline(always)]
    #[must_use]
    pub fn jeoc1(&mut self) -> Jeoc1W<CsrSpec> {
        Jeoc1W::new(self, 2)
    }
    #[doc = "Bit 3 - Injected channel Start flag of ADC 1"]
    #[inline(always)]
    #[must_use]
    pub fn jstrt1(&mut self) -> Jstrt1W<CsrSpec> {
        Jstrt1W::new(self, 3)
    }
    #[doc = "Bit 4 - Regular channel Start flag of ADC 1"]
    #[inline(always)]
    #[must_use]
    pub fn strt1(&mut self) -> Strt1W<CsrSpec> {
        Strt1W::new(self, 4)
    }
    #[doc = "Bit 5 - Overrun flag of ADC 1"]
    #[inline(always)]
    #[must_use]
    pub fn ovr1(&mut self) -> Ovr1W<CsrSpec> {
        Ovr1W::new(self, 5)
    }
    #[doc = "Bit 8 - Analog watchdog flag of ADC 2"]
    #[inline(always)]
    #[must_use]
    pub fn awd2(&mut self) -> Awd2W<CsrSpec> {
        Awd2W::new(self, 8)
    }
    #[doc = "Bit 9 - End of conversion of ADC 2"]
    #[inline(always)]
    #[must_use]
    pub fn eoc2(&mut self) -> Eoc2W<CsrSpec> {
        Eoc2W::new(self, 9)
    }
    #[doc = "Bit 10 - Injected channel end of conversion of ADC 2"]
    #[inline(always)]
    #[must_use]
    pub fn jeoc2(&mut self) -> Jeoc2W<CsrSpec> {
        Jeoc2W::new(self, 10)
    }
    #[doc = "Bit 11 - Injected channel Start flag of ADC 2"]
    #[inline(always)]
    #[must_use]
    pub fn jstrt2(&mut self) -> Jstrt2W<CsrSpec> {
        Jstrt2W::new(self, 11)
    }
    #[doc = "Bit 12 - Regular channel Start flag of ADC 2"]
    #[inline(always)]
    #[must_use]
    pub fn strt2(&mut self) -> Strt2W<CsrSpec> {
        Strt2W::new(self, 12)
    }
    #[doc = "Bit 13 - Overrun flag of ADC 2"]
    #[inline(always)]
    #[must_use]
    pub fn ovr2(&mut self) -> Ovr2W<CsrSpec> {
        Ovr2W::new(self, 13)
    }
    #[doc = "Bit 16 - Analog watchdog flag of ADC 3"]
    #[inline(always)]
    #[must_use]
    pub fn awd3(&mut self) -> Awd3W<CsrSpec> {
        Awd3W::new(self, 16)
    }
    #[doc = "Bit 17 - End of conversion of ADC 3"]
    #[inline(always)]
    #[must_use]
    pub fn eoc3(&mut self) -> Eoc3W<CsrSpec> {
        Eoc3W::new(self, 17)
    }
    #[doc = "Bit 18 - Injected channel end of conversion of ADC 3"]
    #[inline(always)]
    #[must_use]
    pub fn jeoc3(&mut self) -> Jeoc3W<CsrSpec> {
        Jeoc3W::new(self, 18)
    }
    #[doc = "Bit 19 - Injected channel Start flag of ADC 3"]
    #[inline(always)]
    #[must_use]
    pub fn jstrt3(&mut self) -> Jstrt3W<CsrSpec> {
        Jstrt3W::new(self, 19)
    }
    #[doc = "Bit 20 - Regular channel Start flag of ADC 3"]
    #[inline(always)]
    #[must_use]
    pub fn strt3(&mut self) -> Strt3W<CsrSpec> {
        Strt3W::new(self, 20)
    }
    #[doc = "Bit 21 - Overrun flag of ADC3"]
    #[inline(always)]
    #[must_use]
    pub fn ovr3(&mut self) -> Ovr3W<CsrSpec> {
        Ovr3W::new(self, 21)
    }
}
#[doc = "ADC Common status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CsrSpec;
impl crate::RegisterSpec for CsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`csr::R`](R) reader structure"]
impl crate::Readable for CsrSpec {}
#[doc = "`reset()` method sets CSR to value 0"]
impl crate::Resettable for CsrSpec {
    const RESET_VALUE: u32 = 0;
}
