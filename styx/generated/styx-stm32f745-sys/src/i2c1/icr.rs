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
#[doc = "Register `ICR` reader"]
pub type R = crate::R<IcrSpec>;
#[doc = "Register `ICR` writer"]
pub type W = crate::W<IcrSpec>;
#[doc = "Field `ADDRCF` reader - Address Matched flag clear"]
pub type AddrcfR = crate::BitReader;
#[doc = "Field `ADDRCF` writer - Address Matched flag clear"]
pub type AddrcfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NACKCF` reader - Not Acknowledge flag clear"]
pub type NackcfR = crate::BitReader;
#[doc = "Field `NACKCF` writer - Not Acknowledge flag clear"]
pub type NackcfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `STOPCF` reader - Stop detection flag clear"]
pub type StopcfR = crate::BitReader;
#[doc = "Field `STOPCF` writer - Stop detection flag clear"]
pub type StopcfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `BERRCF` reader - Bus error flag clear"]
pub type BerrcfR = crate::BitReader;
#[doc = "Field `BERRCF` writer - Bus error flag clear"]
pub type BerrcfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ARLOCF` reader - Arbitration lost flag clear"]
pub type ArlocfR = crate::BitReader;
#[doc = "Field `ARLOCF` writer - Arbitration lost flag clear"]
pub type ArlocfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OVRCF` reader - Overrun/Underrun flag clear"]
pub type OvrcfR = crate::BitReader;
#[doc = "Field `OVRCF` writer - Overrun/Underrun flag clear"]
pub type OvrcfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PECCF` reader - PEC Error flag clear"]
pub type PeccfR = crate::BitReader;
#[doc = "Field `PECCF` writer - PEC Error flag clear"]
pub type PeccfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TIMOUTCF` reader - Timeout detection flag clear"]
pub type TimoutcfR = crate::BitReader;
#[doc = "Field `TIMOUTCF` writer - Timeout detection flag clear"]
pub type TimoutcfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ALERTCF` reader - Alert flag clear"]
pub type AlertcfR = crate::BitReader;
#[doc = "Field `ALERTCF` writer - Alert flag clear"]
pub type AlertcfW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 3 - Address Matched flag clear"]
    #[inline(always)]
    pub fn addrcf(&self) -> AddrcfR {
        AddrcfR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Not Acknowledge flag clear"]
    #[inline(always)]
    pub fn nackcf(&self) -> NackcfR {
        NackcfR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Stop detection flag clear"]
    #[inline(always)]
    pub fn stopcf(&self) -> StopcfR {
        StopcfR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 8 - Bus error flag clear"]
    #[inline(always)]
    pub fn berrcf(&self) -> BerrcfR {
        BerrcfR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Arbitration lost flag clear"]
    #[inline(always)]
    pub fn arlocf(&self) -> ArlocfR {
        ArlocfR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Overrun/Underrun flag clear"]
    #[inline(always)]
    pub fn ovrcf(&self) -> OvrcfR {
        OvrcfR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - PEC Error flag clear"]
    #[inline(always)]
    pub fn peccf(&self) -> PeccfR {
        PeccfR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 12 - Timeout detection flag clear"]
    #[inline(always)]
    pub fn timoutcf(&self) -> TimoutcfR {
        TimoutcfR::new(((self.bits >> 12) & 1) != 0)
    }
    #[doc = "Bit 13 - Alert flag clear"]
    #[inline(always)]
    pub fn alertcf(&self) -> AlertcfR {
        AlertcfR::new(((self.bits >> 13) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 3 - Address Matched flag clear"]
    #[inline(always)]
    #[must_use]
    pub fn addrcf(&mut self) -> AddrcfW<IcrSpec> {
        AddrcfW::new(self, 3)
    }
    #[doc = "Bit 4 - Not Acknowledge flag clear"]
    #[inline(always)]
    #[must_use]
    pub fn nackcf(&mut self) -> NackcfW<IcrSpec> {
        NackcfW::new(self, 4)
    }
    #[doc = "Bit 5 - Stop detection flag clear"]
    #[inline(always)]
    #[must_use]
    pub fn stopcf(&mut self) -> StopcfW<IcrSpec> {
        StopcfW::new(self, 5)
    }
    #[doc = "Bit 8 - Bus error flag clear"]
    #[inline(always)]
    #[must_use]
    pub fn berrcf(&mut self) -> BerrcfW<IcrSpec> {
        BerrcfW::new(self, 8)
    }
    #[doc = "Bit 9 - Arbitration lost flag clear"]
    #[inline(always)]
    #[must_use]
    pub fn arlocf(&mut self) -> ArlocfW<IcrSpec> {
        ArlocfW::new(self, 9)
    }
    #[doc = "Bit 10 - Overrun/Underrun flag clear"]
    #[inline(always)]
    #[must_use]
    pub fn ovrcf(&mut self) -> OvrcfW<IcrSpec> {
        OvrcfW::new(self, 10)
    }
    #[doc = "Bit 11 - PEC Error flag clear"]
    #[inline(always)]
    #[must_use]
    pub fn peccf(&mut self) -> PeccfW<IcrSpec> {
        PeccfW::new(self, 11)
    }
    #[doc = "Bit 12 - Timeout detection flag clear"]
    #[inline(always)]
    #[must_use]
    pub fn timoutcf(&mut self) -> TimoutcfW<IcrSpec> {
        TimoutcfW::new(self, 12)
    }
    #[doc = "Bit 13 - Alert flag clear"]
    #[inline(always)]
    #[must_use]
    pub fn alertcf(&mut self) -> AlertcfW<IcrSpec> {
        AlertcfW::new(self, 13)
    }
}
#[doc = "Interrupt clear register\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`icr::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcrSpec;
impl crate::RegisterSpec for IcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 28u64;
}
#[doc = "`write(|w| ..)` method takes [`icr::W`](W) writer structure"]
impl crate::Writable for IcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ICR to value 0"]
impl crate::Resettable for IcrSpec {
    const RESET_VALUE: u32 = 0;
}
