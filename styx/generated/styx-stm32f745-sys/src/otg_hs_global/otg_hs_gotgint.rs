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
#[doc = "Register `OTG_HS_GOTGINT` reader"]
pub type R = crate::R<OtgHsGotgintSpec>;
#[doc = "Register `OTG_HS_GOTGINT` writer"]
pub type W = crate::W<OtgHsGotgintSpec>;
#[doc = "Field `SEDET` reader - Session end detected"]
pub type SedetR = crate::BitReader;
#[doc = "Field `SEDET` writer - Session end detected"]
pub type SedetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SRSSCHG` reader - Session request success status change"]
pub type SrsschgR = crate::BitReader;
#[doc = "Field `SRSSCHG` writer - Session request success status change"]
pub type SrsschgW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HNSSCHG` reader - Host negotiation success status change"]
pub type HnsschgR = crate::BitReader;
#[doc = "Field `HNSSCHG` writer - Host negotiation success status change"]
pub type HnsschgW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HNGDET` reader - Host negotiation detected"]
pub type HngdetR = crate::BitReader;
#[doc = "Field `HNGDET` writer - Host negotiation detected"]
pub type HngdetW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADTOCHG` reader - A-device timeout change"]
pub type AdtochgR = crate::BitReader;
#[doc = "Field `ADTOCHG` writer - A-device timeout change"]
pub type AdtochgW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DBCDNE` reader - Debounce done"]
pub type DbcdneR = crate::BitReader;
#[doc = "Field `DBCDNE` writer - Debounce done"]
pub type DbcdneW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `IDCHNG` reader - ID input pin changed"]
pub type IdchngR = crate::BitReader;
#[doc = "Field `IDCHNG` writer - ID input pin changed"]
pub type IdchngW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 2 - Session end detected"]
    #[inline(always)]
    pub fn sedet(&self) -> SedetR {
        SedetR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 8 - Session request success status change"]
    #[inline(always)]
    pub fn srsschg(&self) -> SrsschgR {
        SrsschgR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Host negotiation success status change"]
    #[inline(always)]
    pub fn hnsschg(&self) -> HnsschgR {
        HnsschgR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 17 - Host negotiation detected"]
    #[inline(always)]
    pub fn hngdet(&self) -> HngdetR {
        HngdetR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - A-device timeout change"]
    #[inline(always)]
    pub fn adtochg(&self) -> AdtochgR {
        AdtochgR::new(((self.bits >> 18) & 1) != 0)
    }
    #[doc = "Bit 19 - Debounce done"]
    #[inline(always)]
    pub fn dbcdne(&self) -> DbcdneR {
        DbcdneR::new(((self.bits >> 19) & 1) != 0)
    }
    #[doc = "Bit 20 - ID input pin changed"]
    #[inline(always)]
    pub fn idchng(&self) -> IdchngR {
        IdchngR::new(((self.bits >> 20) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 2 - Session end detected"]
    #[inline(always)]
    #[must_use]
    pub fn sedet(&mut self) -> SedetW<OtgHsGotgintSpec> {
        SedetW::new(self, 2)
    }
    #[doc = "Bit 8 - Session request success status change"]
    #[inline(always)]
    #[must_use]
    pub fn srsschg(&mut self) -> SrsschgW<OtgHsGotgintSpec> {
        SrsschgW::new(self, 8)
    }
    #[doc = "Bit 9 - Host negotiation success status change"]
    #[inline(always)]
    #[must_use]
    pub fn hnsschg(&mut self) -> HnsschgW<OtgHsGotgintSpec> {
        HnsschgW::new(self, 9)
    }
    #[doc = "Bit 17 - Host negotiation detected"]
    #[inline(always)]
    #[must_use]
    pub fn hngdet(&mut self) -> HngdetW<OtgHsGotgintSpec> {
        HngdetW::new(self, 17)
    }
    #[doc = "Bit 18 - A-device timeout change"]
    #[inline(always)]
    #[must_use]
    pub fn adtochg(&mut self) -> AdtochgW<OtgHsGotgintSpec> {
        AdtochgW::new(self, 18)
    }
    #[doc = "Bit 19 - Debounce done"]
    #[inline(always)]
    #[must_use]
    pub fn dbcdne(&mut self) -> DbcdneW<OtgHsGotgintSpec> {
        DbcdneW::new(self, 19)
    }
    #[doc = "Bit 20 - ID input pin changed"]
    #[inline(always)]
    #[must_use]
    pub fn idchng(&mut self) -> IdchngW<OtgHsGotgintSpec> {
        IdchngW::new(self, 20)
    }
}
#[doc = "OTG_HS interrupt register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_gotgint::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_gotgint::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsGotgintSpec;
impl crate::RegisterSpec for OtgHsGotgintSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`otg_hs_gotgint::R`](R) reader structure"]
impl crate::Readable for OtgHsGotgintSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_hs_gotgint::W`](W) writer structure"]
impl crate::Writable for OtgHsGotgintSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_HS_GOTGINT to value 0"]
impl crate::Resettable for OtgHsGotgintSpec {
    const RESET_VALUE: u32 = 0;
}
