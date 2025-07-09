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
#[doc = "Register `ITCMCR` reader"]
pub type R = crate::R<ItcmcrSpec>;
#[doc = "Register `ITCMCR` writer"]
pub type W = crate::W<ItcmcrSpec>;
#[doc = "Field `EN` reader - EN"]
pub type EnR = crate::BitReader;
#[doc = "Field `EN` writer - EN"]
pub type EnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RMW` reader - RMW"]
pub type RmwR = crate::BitReader;
#[doc = "Field `RMW` writer - RMW"]
pub type RmwW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RETEN` reader - RETEN"]
pub type RetenR = crate::BitReader;
#[doc = "Field `RETEN` writer - RETEN"]
pub type RetenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `SZ` reader - SZ"]
pub type SzR = crate::FieldReader;
#[doc = "Field `SZ` writer - SZ"]
pub type SzW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bit 0 - EN"]
    #[inline(always)]
    pub fn en(&self) -> EnR {
        EnR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - RMW"]
    #[inline(always)]
    pub fn rmw(&self) -> RmwR {
        RmwR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - RETEN"]
    #[inline(always)]
    pub fn reten(&self) -> RetenR {
        RetenR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bits 3:6 - SZ"]
    #[inline(always)]
    pub fn sz(&self) -> SzR {
        SzR::new(((self.bits >> 3) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - EN"]
    #[inline(always)]
    #[must_use]
    pub fn en(&mut self) -> EnW<ItcmcrSpec> {
        EnW::new(self, 0)
    }
    #[doc = "Bit 1 - RMW"]
    #[inline(always)]
    #[must_use]
    pub fn rmw(&mut self) -> RmwW<ItcmcrSpec> {
        RmwW::new(self, 1)
    }
    #[doc = "Bit 2 - RETEN"]
    #[inline(always)]
    #[must_use]
    pub fn reten(&mut self) -> RetenW<ItcmcrSpec> {
        RetenW::new(self, 2)
    }
    #[doc = "Bits 3:6 - SZ"]
    #[inline(always)]
    #[must_use]
    pub fn sz(&mut self) -> SzW<ItcmcrSpec> {
        SzW::new(self, 3)
    }
}
#[doc = "Instruction and Data Tightly-Coupled Memory Control Registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`itcmcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`itcmcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ItcmcrSpec;
impl crate::RegisterSpec for ItcmcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`itcmcr::R`](R) reader structure"]
impl crate::Readable for ItcmcrSpec {}
#[doc = "`write(|w| ..)` method takes [`itcmcr::W`](W) writer structure"]
impl crate::Writable for ItcmcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ITCMCR to value 0"]
impl crate::Resettable for ItcmcrSpec {
    const RESET_VALUE: u32 = 0;
}
