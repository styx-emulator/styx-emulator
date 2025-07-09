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
#[doc = "Register `MIS` reader"]
pub type R = crate::R<MisSpec>;
#[doc = "Register `MIS` writer"]
pub type W = crate::W<MisSpec>;
#[doc = "Field `FRAME_MIS` reader - Capture complete masked interrupt status"]
pub type FrameMisR = crate::BitReader;
#[doc = "Field `FRAME_MIS` writer - Capture complete masked interrupt status"]
pub type FrameMisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OVR_MIS` reader - Overrun masked interrupt status"]
pub type OvrMisR = crate::BitReader;
#[doc = "Field `OVR_MIS` writer - Overrun masked interrupt status"]
pub type OvrMisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ERR_MIS` reader - Synchronization error masked interrupt status"]
pub type ErrMisR = crate::BitReader;
#[doc = "Field `ERR_MIS` writer - Synchronization error masked interrupt status"]
pub type ErrMisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `VSYNC_MIS` reader - VSYNC masked interrupt status"]
pub type VsyncMisR = crate::BitReader;
#[doc = "Field `VSYNC_MIS` writer - VSYNC masked interrupt status"]
pub type VsyncMisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LINE_MIS` reader - Line masked interrupt status"]
pub type LineMisR = crate::BitReader;
#[doc = "Field `LINE_MIS` writer - Line masked interrupt status"]
pub type LineMisW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Capture complete masked interrupt status"]
    #[inline(always)]
    pub fn frame_mis(&self) -> FrameMisR {
        FrameMisR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Overrun masked interrupt status"]
    #[inline(always)]
    pub fn ovr_mis(&self) -> OvrMisR {
        OvrMisR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Synchronization error masked interrupt status"]
    #[inline(always)]
    pub fn err_mis(&self) -> ErrMisR {
        ErrMisR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - VSYNC masked interrupt status"]
    #[inline(always)]
    pub fn vsync_mis(&self) -> VsyncMisR {
        VsyncMisR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Line masked interrupt status"]
    #[inline(always)]
    pub fn line_mis(&self) -> LineMisR {
        LineMisR::new(((self.bits >> 4) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Capture complete masked interrupt status"]
    #[inline(always)]
    #[must_use]
    pub fn frame_mis(&mut self) -> FrameMisW<MisSpec> {
        FrameMisW::new(self, 0)
    }
    #[doc = "Bit 1 - Overrun masked interrupt status"]
    #[inline(always)]
    #[must_use]
    pub fn ovr_mis(&mut self) -> OvrMisW<MisSpec> {
        OvrMisW::new(self, 1)
    }
    #[doc = "Bit 2 - Synchronization error masked interrupt status"]
    #[inline(always)]
    #[must_use]
    pub fn err_mis(&mut self) -> ErrMisW<MisSpec> {
        ErrMisW::new(self, 2)
    }
    #[doc = "Bit 3 - VSYNC masked interrupt status"]
    #[inline(always)]
    #[must_use]
    pub fn vsync_mis(&mut self) -> VsyncMisW<MisSpec> {
        VsyncMisW::new(self, 3)
    }
    #[doc = "Bit 4 - Line masked interrupt status"]
    #[inline(always)]
    #[must_use]
    pub fn line_mis(&mut self) -> LineMisW<MisSpec> {
        LineMisW::new(self, 4)
    }
}
#[doc = "masked interrupt status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mis::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MisSpec;
impl crate::RegisterSpec for MisSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`mis::R`](R) reader structure"]
impl crate::Readable for MisSpec {}
#[doc = "`reset()` method sets MIS to value 0"]
impl crate::Resettable for MisSpec {
    const RESET_VALUE: u32 = 0;
}
