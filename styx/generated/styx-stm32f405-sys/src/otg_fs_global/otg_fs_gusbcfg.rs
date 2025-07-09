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
#[doc = "Register `OTG_FS_GUSBCFG` reader"]
pub type R = crate::R<OtgFsGusbcfgSpec>;
#[doc = "Register `OTG_FS_GUSBCFG` writer"]
pub type W = crate::W<OtgFsGusbcfgSpec>;
#[doc = "Field `TOCAL` reader - FS timeout calibration"]
pub type TocalR = crate::FieldReader;
#[doc = "Field `TOCAL` writer - FS timeout calibration"]
pub type TocalW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `PHYSEL` reader - Full Speed serial transceiver select"]
pub type PhyselR = crate::BitReader;
#[doc = "Field `PHYSEL` writer - Full Speed serial transceiver select"]
pub type PhyselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SRPCAP` reader - SRP-capable"]
pub type SrpcapR = crate::BitReader;
#[doc = "Field `SRPCAP` writer - SRP-capable"]
pub type SrpcapW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `HNPCAP` reader - HNP-capable"]
pub type HnpcapR = crate::BitReader;
#[doc = "Field `HNPCAP` writer - HNP-capable"]
pub type HnpcapW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TRDT` reader - USB turnaround time"]
pub type TrdtR = crate::FieldReader;
#[doc = "Field `TRDT` writer - USB turnaround time"]
pub type TrdtW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `FHMOD` reader - Force host mode"]
pub type FhmodR = crate::BitReader;
#[doc = "Field `FHMOD` writer - Force host mode"]
pub type FhmodW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FDMOD` reader - Force device mode"]
pub type FdmodR = crate::BitReader;
#[doc = "Field `FDMOD` writer - Force device mode"]
pub type FdmodW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:2 - FS timeout calibration"]
    #[inline(always)]
    pub fn tocal(&self) -> TocalR {
        TocalR::new((self.bits & 7) as u8)
    }
    #[doc = "Bit 6 - Full Speed serial transceiver select"]
    #[inline(always)]
    pub fn physel(&self) -> PhyselR {
        PhyselR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bit 8 - SRP-capable"]
    #[inline(always)]
    pub fn srpcap(&self) -> SrpcapR {
        SrpcapR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - HNP-capable"]
    #[inline(always)]
    pub fn hnpcap(&self) -> HnpcapR {
        HnpcapR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bits 10:13 - USB turnaround time"]
    #[inline(always)]
    pub fn trdt(&self) -> TrdtR {
        TrdtR::new(((self.bits >> 10) & 0x0f) as u8)
    }
    #[doc = "Bit 29 - Force host mode"]
    #[inline(always)]
    pub fn fhmod(&self) -> FhmodR {
        FhmodR::new(((self.bits >> 29) & 1) != 0)
    }
    #[doc = "Bit 30 - Force device mode"]
    #[inline(always)]
    pub fn fdmod(&self) -> FdmodR {
        FdmodR::new(((self.bits >> 30) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:2 - FS timeout calibration"]
    #[inline(always)]
    #[must_use]
    pub fn tocal(&mut self) -> TocalW<OtgFsGusbcfgSpec> {
        TocalW::new(self, 0)
    }
    #[doc = "Bit 6 - Full Speed serial transceiver select"]
    #[inline(always)]
    #[must_use]
    pub fn physel(&mut self) -> PhyselW<OtgFsGusbcfgSpec> {
        PhyselW::new(self, 6)
    }
    #[doc = "Bit 8 - SRP-capable"]
    #[inline(always)]
    #[must_use]
    pub fn srpcap(&mut self) -> SrpcapW<OtgFsGusbcfgSpec> {
        SrpcapW::new(self, 8)
    }
    #[doc = "Bit 9 - HNP-capable"]
    #[inline(always)]
    #[must_use]
    pub fn hnpcap(&mut self) -> HnpcapW<OtgFsGusbcfgSpec> {
        HnpcapW::new(self, 9)
    }
    #[doc = "Bits 10:13 - USB turnaround time"]
    #[inline(always)]
    #[must_use]
    pub fn trdt(&mut self) -> TrdtW<OtgFsGusbcfgSpec> {
        TrdtW::new(self, 10)
    }
    #[doc = "Bit 29 - Force host mode"]
    #[inline(always)]
    #[must_use]
    pub fn fhmod(&mut self) -> FhmodW<OtgFsGusbcfgSpec> {
        FhmodW::new(self, 29)
    }
    #[doc = "Bit 30 - Force device mode"]
    #[inline(always)]
    #[must_use]
    pub fn fdmod(&mut self) -> FdmodW<OtgFsGusbcfgSpec> {
        FdmodW::new(self, 30)
    }
}
#[doc = "OTG_FS USB configuration register (OTG_FS_GUSBCFG)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_gusbcfg::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_fs_gusbcfg::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsGusbcfgSpec;
impl crate::RegisterSpec for OtgFsGusbcfgSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`otg_fs_gusbcfg::R`](R) reader structure"]
impl crate::Readable for OtgFsGusbcfgSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_fs_gusbcfg::W`](W) writer structure"]
impl crate::Writable for OtgFsGusbcfgSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_FS_GUSBCFG to value 0x0a00"]
impl crate::Resettable for OtgFsGusbcfgSpec {
    const RESET_VALUE: u32 = 0x0a00;
}
