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
#[doc = "Register `OTG_HS_HCSPLT11` reader"]
pub type R = crate::R<OtgHsHcsplt11Spec>;
#[doc = "Register `OTG_HS_HCSPLT11` writer"]
pub type W = crate::W<OtgHsHcsplt11Spec>;
#[doc = "Field `PRTADDR` reader - Port address"]
pub type PrtaddrR = crate::FieldReader;
#[doc = "Field `PRTADDR` writer - Port address"]
pub type PrtaddrW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
#[doc = "Field `HUBADDR` reader - Hub address"]
pub type HubaddrR = crate::FieldReader;
#[doc = "Field `HUBADDR` writer - Hub address"]
pub type HubaddrW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
#[doc = "Field `XACTPOS` reader - XACTPOS"]
pub type XactposR = crate::FieldReader;
#[doc = "Field `XACTPOS` writer - XACTPOS"]
pub type XactposW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `COMPLSPLT` reader - Do complete split"]
pub type ComplspltR = crate::BitReader;
#[doc = "Field `COMPLSPLT` writer - Do complete split"]
pub type ComplspltW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SPLITEN` reader - Split enable"]
pub type SplitenR = crate::BitReader;
#[doc = "Field `SPLITEN` writer - Split enable"]
pub type SplitenW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:6 - Port address"]
    #[inline(always)]
    pub fn prtaddr(&self) -> PrtaddrR {
        PrtaddrR::new((self.bits & 0x7f) as u8)
    }
    #[doc = "Bits 7:13 - Hub address"]
    #[inline(always)]
    pub fn hubaddr(&self) -> HubaddrR {
        HubaddrR::new(((self.bits >> 7) & 0x7f) as u8)
    }
    #[doc = "Bits 14:15 - XACTPOS"]
    #[inline(always)]
    pub fn xactpos(&self) -> XactposR {
        XactposR::new(((self.bits >> 14) & 3) as u8)
    }
    #[doc = "Bit 16 - Do complete split"]
    #[inline(always)]
    pub fn complsplt(&self) -> ComplspltR {
        ComplspltR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 31 - Split enable"]
    #[inline(always)]
    pub fn spliten(&self) -> SplitenR {
        SplitenR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:6 - Port address"]
    #[inline(always)]
    #[must_use]
    pub fn prtaddr(&mut self) -> PrtaddrW<OtgHsHcsplt11Spec> {
        PrtaddrW::new(self, 0)
    }
    #[doc = "Bits 7:13 - Hub address"]
    #[inline(always)]
    #[must_use]
    pub fn hubaddr(&mut self) -> HubaddrW<OtgHsHcsplt11Spec> {
        HubaddrW::new(self, 7)
    }
    #[doc = "Bits 14:15 - XACTPOS"]
    #[inline(always)]
    #[must_use]
    pub fn xactpos(&mut self) -> XactposW<OtgHsHcsplt11Spec> {
        XactposW::new(self, 14)
    }
    #[doc = "Bit 16 - Do complete split"]
    #[inline(always)]
    #[must_use]
    pub fn complsplt(&mut self) -> ComplspltW<OtgHsHcsplt11Spec> {
        ComplspltW::new(self, 16)
    }
    #[doc = "Bit 31 - Split enable"]
    #[inline(always)]
    #[must_use]
    pub fn spliten(&mut self) -> SplitenW<OtgHsHcsplt11Spec> {
        SplitenW::new(self, 31)
    }
}
#[doc = "OTG_HS host channel-11 split control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_hcsplt11::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_hcsplt11::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsHcsplt11Spec;
impl crate::RegisterSpec for OtgHsHcsplt11Spec {
    type Ux = u32;
    const OFFSET: u64 = 612u64;
}
#[doc = "`read()` method returns [`otg_hs_hcsplt11::R`](R) reader structure"]
impl crate::Readable for OtgHsHcsplt11Spec {}
#[doc = "`write(|w| ..)` method takes [`otg_hs_hcsplt11::W`](W) writer structure"]
impl crate::Writable for OtgHsHcsplt11Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_HS_HCSPLT11 to value 0"]
impl crate::Resettable for OtgHsHcsplt11Spec {
    const RESET_VALUE: u32 = 0;
}
