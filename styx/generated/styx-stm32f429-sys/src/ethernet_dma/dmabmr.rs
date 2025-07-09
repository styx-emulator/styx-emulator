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
#[doc = "Register `DMABMR` reader"]
pub type R = crate::R<DmabmrSpec>;
#[doc = "Register `DMABMR` writer"]
pub type W = crate::W<DmabmrSpec>;
#[doc = "Field `SR` reader - SR"]
pub type SrR = crate::BitReader;
#[doc = "Field `SR` writer - SR"]
pub type SrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DA` reader - DA"]
pub type DaR = crate::BitReader;
#[doc = "Field `DA` writer - DA"]
pub type DaW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DSL` reader - DSL"]
pub type DslR = crate::FieldReader;
#[doc = "Field `DSL` writer - DSL"]
pub type DslW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
#[doc = "Field `EDFE` reader - EDFE"]
pub type EdfeR = crate::BitReader;
#[doc = "Field `EDFE` writer - EDFE"]
pub type EdfeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PBL` reader - PBL"]
pub type PblR = crate::FieldReader;
#[doc = "Field `PBL` writer - PBL"]
pub type PblW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
#[doc = "Field `RTPR` reader - RTPR"]
pub type RtprR = crate::FieldReader;
#[doc = "Field `RTPR` writer - RTPR"]
pub type RtprW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `FB` reader - FB"]
pub type FbR = crate::BitReader;
#[doc = "Field `FB` writer - FB"]
pub type FbW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RDP` reader - RDP"]
pub type RdpR = crate::FieldReader;
#[doc = "Field `RDP` writer - RDP"]
pub type RdpW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
#[doc = "Field `USP` reader - USP"]
pub type UspR = crate::BitReader;
#[doc = "Field `USP` writer - USP"]
pub type UspW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FPM` reader - FPM"]
pub type FpmR = crate::BitReader;
#[doc = "Field `FPM` writer - FPM"]
pub type FpmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `AAB` reader - AAB"]
pub type AabR = crate::BitReader;
#[doc = "Field `AAB` writer - AAB"]
pub type AabW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MB` reader - MB"]
pub type MbR = crate::BitReader;
#[doc = "Field `MB` writer - MB"]
pub type MbW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - SR"]
    #[inline(always)]
    pub fn sr(&self) -> SrR {
        SrR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - DA"]
    #[inline(always)]
    pub fn da(&self) -> DaR {
        DaR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bits 2:6 - DSL"]
    #[inline(always)]
    pub fn dsl(&self) -> DslR {
        DslR::new(((self.bits >> 2) & 0x1f) as u8)
    }
    #[doc = "Bit 7 - EDFE"]
    #[inline(always)]
    pub fn edfe(&self) -> EdfeR {
        EdfeR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 8:13 - PBL"]
    #[inline(always)]
    pub fn pbl(&self) -> PblR {
        PblR::new(((self.bits >> 8) & 0x3f) as u8)
    }
    #[doc = "Bits 14:15 - RTPR"]
    #[inline(always)]
    pub fn rtpr(&self) -> RtprR {
        RtprR::new(((self.bits >> 14) & 3) as u8)
    }
    #[doc = "Bit 16 - FB"]
    #[inline(always)]
    pub fn fb(&self) -> FbR {
        FbR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bits 17:22 - RDP"]
    #[inline(always)]
    pub fn rdp(&self) -> RdpR {
        RdpR::new(((self.bits >> 17) & 0x3f) as u8)
    }
    #[doc = "Bit 23 - USP"]
    #[inline(always)]
    pub fn usp(&self) -> UspR {
        UspR::new(((self.bits >> 23) & 1) != 0)
    }
    #[doc = "Bit 24 - FPM"]
    #[inline(always)]
    pub fn fpm(&self) -> FpmR {
        FpmR::new(((self.bits >> 24) & 1) != 0)
    }
    #[doc = "Bit 25 - AAB"]
    #[inline(always)]
    pub fn aab(&self) -> AabR {
        AabR::new(((self.bits >> 25) & 1) != 0)
    }
    #[doc = "Bit 26 - MB"]
    #[inline(always)]
    pub fn mb(&self) -> MbR {
        MbR::new(((self.bits >> 26) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - SR"]
    #[inline(always)]
    #[must_use]
    pub fn sr(&mut self) -> SrW<DmabmrSpec> {
        SrW::new(self, 0)
    }
    #[doc = "Bit 1 - DA"]
    #[inline(always)]
    #[must_use]
    pub fn da(&mut self) -> DaW<DmabmrSpec> {
        DaW::new(self, 1)
    }
    #[doc = "Bits 2:6 - DSL"]
    #[inline(always)]
    #[must_use]
    pub fn dsl(&mut self) -> DslW<DmabmrSpec> {
        DslW::new(self, 2)
    }
    #[doc = "Bit 7 - EDFE"]
    #[inline(always)]
    #[must_use]
    pub fn edfe(&mut self) -> EdfeW<DmabmrSpec> {
        EdfeW::new(self, 7)
    }
    #[doc = "Bits 8:13 - PBL"]
    #[inline(always)]
    #[must_use]
    pub fn pbl(&mut self) -> PblW<DmabmrSpec> {
        PblW::new(self, 8)
    }
    #[doc = "Bits 14:15 - RTPR"]
    #[inline(always)]
    #[must_use]
    pub fn rtpr(&mut self) -> RtprW<DmabmrSpec> {
        RtprW::new(self, 14)
    }
    #[doc = "Bit 16 - FB"]
    #[inline(always)]
    #[must_use]
    pub fn fb(&mut self) -> FbW<DmabmrSpec> {
        FbW::new(self, 16)
    }
    #[doc = "Bits 17:22 - RDP"]
    #[inline(always)]
    #[must_use]
    pub fn rdp(&mut self) -> RdpW<DmabmrSpec> {
        RdpW::new(self, 17)
    }
    #[doc = "Bit 23 - USP"]
    #[inline(always)]
    #[must_use]
    pub fn usp(&mut self) -> UspW<DmabmrSpec> {
        UspW::new(self, 23)
    }
    #[doc = "Bit 24 - FPM"]
    #[inline(always)]
    #[must_use]
    pub fn fpm(&mut self) -> FpmW<DmabmrSpec> {
        FpmW::new(self, 24)
    }
    #[doc = "Bit 25 - AAB"]
    #[inline(always)]
    #[must_use]
    pub fn aab(&mut self) -> AabW<DmabmrSpec> {
        AabW::new(self, 25)
    }
    #[doc = "Bit 26 - MB"]
    #[inline(always)]
    #[must_use]
    pub fn mb(&mut self) -> MbW<DmabmrSpec> {
        MbW::new(self, 26)
    }
}
#[doc = "Ethernet DMA bus mode register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmabmr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmabmr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmabmrSpec;
impl crate::RegisterSpec for DmabmrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`dmabmr::R`](R) reader structure"]
impl crate::Readable for DmabmrSpec {}
#[doc = "`write(|w| ..)` method takes [`dmabmr::W`](W) writer structure"]
impl crate::Writable for DmabmrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets DMABMR to value 0x2101"]
impl crate::Resettable for DmabmrSpec {
    const RESET_VALUE: u32 = 0x2101;
}
