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
#[doc = "Field `CMPMCF` reader - compare match Clear Flag"]
pub type CmpmcfR = crate::BitReader;
#[doc = "Field `CMPMCF` writer - compare match Clear Flag"]
pub type CmpmcfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ARRMCF` reader - Autoreload match Clear Flag"]
pub type ArrmcfR = crate::BitReader;
#[doc = "Field `ARRMCF` writer - Autoreload match Clear Flag"]
pub type ArrmcfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EXTTRIGCF` reader - External trigger valid edge Clear Flag"]
pub type ExttrigcfR = crate::BitReader;
#[doc = "Field `EXTTRIGCF` writer - External trigger valid edge Clear Flag"]
pub type ExttrigcfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CMPOKCF` reader - Compare register update OK Clear Flag"]
pub type CmpokcfR = crate::BitReader;
#[doc = "Field `CMPOKCF` writer - Compare register update OK Clear Flag"]
pub type CmpokcfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ARROKCF` reader - Autoreload register update OK Clear Flag"]
pub type ArrokcfR = crate::BitReader;
#[doc = "Field `ARROKCF` writer - Autoreload register update OK Clear Flag"]
pub type ArrokcfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `UPCF` reader - Direction change to UP Clear Flag"]
pub type UpcfR = crate::BitReader;
#[doc = "Field `UPCF` writer - Direction change to UP Clear Flag"]
pub type UpcfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DOWNCF` reader - Direction change to down Clear Flag"]
pub type DowncfR = crate::BitReader;
#[doc = "Field `DOWNCF` writer - Direction change to down Clear Flag"]
pub type DowncfW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - compare match Clear Flag"]
    #[inline(always)]
    pub fn cmpmcf(&self) -> CmpmcfR {
        CmpmcfR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Autoreload match Clear Flag"]
    #[inline(always)]
    pub fn arrmcf(&self) -> ArrmcfR {
        ArrmcfR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - External trigger valid edge Clear Flag"]
    #[inline(always)]
    pub fn exttrigcf(&self) -> ExttrigcfR {
        ExttrigcfR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Compare register update OK Clear Flag"]
    #[inline(always)]
    pub fn cmpokcf(&self) -> CmpokcfR {
        CmpokcfR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Autoreload register update OK Clear Flag"]
    #[inline(always)]
    pub fn arrokcf(&self) -> ArrokcfR {
        ArrokcfR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Direction change to UP Clear Flag"]
    #[inline(always)]
    pub fn upcf(&self) -> UpcfR {
        UpcfR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Direction change to down Clear Flag"]
    #[inline(always)]
    pub fn downcf(&self) -> DowncfR {
        DowncfR::new(((self.bits >> 6) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - compare match Clear Flag"]
    #[inline(always)]
    #[must_use]
    pub fn cmpmcf(&mut self) -> CmpmcfW<IcrSpec> {
        CmpmcfW::new(self, 0)
    }
    #[doc = "Bit 1 - Autoreload match Clear Flag"]
    #[inline(always)]
    #[must_use]
    pub fn arrmcf(&mut self) -> ArrmcfW<IcrSpec> {
        ArrmcfW::new(self, 1)
    }
    #[doc = "Bit 2 - External trigger valid edge Clear Flag"]
    #[inline(always)]
    #[must_use]
    pub fn exttrigcf(&mut self) -> ExttrigcfW<IcrSpec> {
        ExttrigcfW::new(self, 2)
    }
    #[doc = "Bit 3 - Compare register update OK Clear Flag"]
    #[inline(always)]
    #[must_use]
    pub fn cmpokcf(&mut self) -> CmpokcfW<IcrSpec> {
        CmpokcfW::new(self, 3)
    }
    #[doc = "Bit 4 - Autoreload register update OK Clear Flag"]
    #[inline(always)]
    #[must_use]
    pub fn arrokcf(&mut self) -> ArrokcfW<IcrSpec> {
        ArrokcfW::new(self, 4)
    }
    #[doc = "Bit 5 - Direction change to UP Clear Flag"]
    #[inline(always)]
    #[must_use]
    pub fn upcf(&mut self) -> UpcfW<IcrSpec> {
        UpcfW::new(self, 5)
    }
    #[doc = "Bit 6 - Direction change to down Clear Flag"]
    #[inline(always)]
    #[must_use]
    pub fn downcf(&mut self) -> DowncfW<IcrSpec> {
        DowncfW::new(self, 6)
    }
}
#[doc = "Interrupt Clear Register\n\nYou can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`icr::W`](W). See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcrSpec;
impl crate::RegisterSpec for IcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
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
