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
#[doc = "Register `RIS` reader"]
pub type R = crate::R<RisSpec>;
#[doc = "Register `RIS` writer"]
pub type W = crate::W<RisSpec>;
#[doc = "Field `FRAME_RIS` reader - Capture complete raw interrupt status"]
pub type FrameRisR = crate::BitReader;
#[doc = "Field `FRAME_RIS` writer - Capture complete raw interrupt status"]
pub type FrameRisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OVR_RIS` reader - Overrun raw interrupt status"]
pub type OvrRisR = crate::BitReader;
#[doc = "Field `OVR_RIS` writer - Overrun raw interrupt status"]
pub type OvrRisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ERR_RIS` reader - Synchronization error raw interrupt status"]
pub type ErrRisR = crate::BitReader;
#[doc = "Field `ERR_RIS` writer - Synchronization error raw interrupt status"]
pub type ErrRisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `VSYNC_RIS` reader - VSYNC raw interrupt status"]
pub type VsyncRisR = crate::BitReader;
#[doc = "Field `VSYNC_RIS` writer - VSYNC raw interrupt status"]
pub type VsyncRisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LINE_RIS` reader - Line raw interrupt status"]
pub type LineRisR = crate::BitReader;
#[doc = "Field `LINE_RIS` writer - Line raw interrupt status"]
pub type LineRisW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Capture complete raw interrupt status"]
    #[inline(always)]
    pub fn frame_ris(&self) -> FrameRisR {
        FrameRisR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Overrun raw interrupt status"]
    #[inline(always)]
    pub fn ovr_ris(&self) -> OvrRisR {
        OvrRisR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Synchronization error raw interrupt status"]
    #[inline(always)]
    pub fn err_ris(&self) -> ErrRisR {
        ErrRisR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - VSYNC raw interrupt status"]
    #[inline(always)]
    pub fn vsync_ris(&self) -> VsyncRisR {
        VsyncRisR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Line raw interrupt status"]
    #[inline(always)]
    pub fn line_ris(&self) -> LineRisR {
        LineRisR::new(((self.bits >> 4) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Capture complete raw interrupt status"]
    #[inline(always)]
    #[must_use]
    pub fn frame_ris(&mut self) -> FrameRisW<RisSpec> {
        FrameRisW::new(self, 0)
    }
    #[doc = "Bit 1 - Overrun raw interrupt status"]
    #[inline(always)]
    #[must_use]
    pub fn ovr_ris(&mut self) -> OvrRisW<RisSpec> {
        OvrRisW::new(self, 1)
    }
    #[doc = "Bit 2 - Synchronization error raw interrupt status"]
    #[inline(always)]
    #[must_use]
    pub fn err_ris(&mut self) -> ErrRisW<RisSpec> {
        ErrRisW::new(self, 2)
    }
    #[doc = "Bit 3 - VSYNC raw interrupt status"]
    #[inline(always)]
    #[must_use]
    pub fn vsync_ris(&mut self) -> VsyncRisW<RisSpec> {
        VsyncRisW::new(self, 3)
    }
    #[doc = "Bit 4 - Line raw interrupt status"]
    #[inline(always)]
    #[must_use]
    pub fn line_ris(&mut self) -> LineRisW<RisSpec> {
        LineRisW::new(self, 4)
    }
}
#[doc = "raw interrupt status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ris::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RisSpec;
impl crate::RegisterSpec for RisSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`ris::R`](R) reader structure"]
impl crate::Readable for RisSpec {}
#[doc = "`reset()` method sets RIS to value 0"]
impl crate::Resettable for RisSpec {
    const RESET_VALUE: u32 = 0;
}
