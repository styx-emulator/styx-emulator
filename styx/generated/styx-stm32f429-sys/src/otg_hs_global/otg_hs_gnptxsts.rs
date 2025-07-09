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
#[doc = "Register `OTG_HS_GNPTXSTS` reader"]
pub type R = crate::R<OtgHsGnptxstsSpec>;
#[doc = "Register `OTG_HS_GNPTXSTS` writer"]
pub type W = crate::W<OtgHsGnptxstsSpec>;
#[doc = "Field `NPTXFSAV` reader - Nonperiodic TxFIFO space available"]
pub type NptxfsavR = crate::FieldReader<u16>;
#[doc = "Field `NPTXFSAV` writer - Nonperiodic TxFIFO space available"]
pub type NptxfsavW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `NPTQXSAV` reader - Nonperiodic transmit request queue space available"]
pub type NptqxsavR = crate::FieldReader;
#[doc = "Field `NPTQXSAV` writer - Nonperiodic transmit request queue space available"]
pub type NptqxsavW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `NPTXQTOP` reader - Top of the nonperiodic transmit request queue"]
pub type NptxqtopR = crate::FieldReader;
#[doc = "Field `NPTXQTOP` writer - Top of the nonperiodic transmit request queue"]
pub type NptxqtopW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
impl R {
    #[doc = "Bits 0:15 - Nonperiodic TxFIFO space available"]
    #[inline(always)]
    pub fn nptxfsav(&self) -> NptxfsavR {
        NptxfsavR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:23 - Nonperiodic transmit request queue space available"]
    #[inline(always)]
    pub fn nptqxsav(&self) -> NptqxsavR {
        NptqxsavR::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bits 24:30 - Top of the nonperiodic transmit request queue"]
    #[inline(always)]
    pub fn nptxqtop(&self) -> NptxqtopR {
        NptxqtopR::new(((self.bits >> 24) & 0x7f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:15 - Nonperiodic TxFIFO space available"]
    #[inline(always)]
    #[must_use]
    pub fn nptxfsav(&mut self) -> NptxfsavW<OtgHsGnptxstsSpec> {
        NptxfsavW::new(self, 0)
    }
    #[doc = "Bits 16:23 - Nonperiodic transmit request queue space available"]
    #[inline(always)]
    #[must_use]
    pub fn nptqxsav(&mut self) -> NptqxsavW<OtgHsGnptxstsSpec> {
        NptqxsavW::new(self, 16)
    }
    #[doc = "Bits 24:30 - Top of the nonperiodic transmit request queue"]
    #[inline(always)]
    #[must_use]
    pub fn nptxqtop(&mut self) -> NptxqtopW<OtgHsGnptxstsSpec> {
        NptxqtopW::new(self, 24)
    }
}
#[doc = "OTG_HS nonperiodic transmit FIFO/queue status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_gnptxsts::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsGnptxstsSpec;
impl crate::RegisterSpec for OtgHsGnptxstsSpec {
    type Ux = u32;
    const OFFSET: u64 = 44u64;
}
#[doc = "`read()` method returns [`otg_hs_gnptxsts::R`](R) reader structure"]
impl crate::Readable for OtgHsGnptxstsSpec {}
#[doc = "`reset()` method sets OTG_HS_GNPTXSTS to value 0x0008_0200"]
impl crate::Resettable for OtgHsGnptxstsSpec {
    const RESET_VALUE: u32 = 0x0008_0200;
}
