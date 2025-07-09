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
#[doc = "Register `IER` reader"]
pub type R = crate::R<IerSpec>;
#[doc = "Register `IER` writer"]
pub type W = crate::W<IerSpec>;
#[doc = "Field `FRAME_IE` reader - Capture complete interrupt enable"]
pub type FrameIeR = crate::BitReader;
#[doc = "Field `FRAME_IE` writer - Capture complete interrupt enable"]
pub type FrameIeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OVR_IE` reader - Overrun interrupt enable"]
pub type OvrIeR = crate::BitReader;
#[doc = "Field `OVR_IE` writer - Overrun interrupt enable"]
pub type OvrIeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ERR_IE` reader - Synchronization error interrupt enable"]
pub type ErrIeR = crate::BitReader;
#[doc = "Field `ERR_IE` writer - Synchronization error interrupt enable"]
pub type ErrIeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `VSYNC_IE` reader - VSYNC interrupt enable"]
pub type VsyncIeR = crate::BitReader;
#[doc = "Field `VSYNC_IE` writer - VSYNC interrupt enable"]
pub type VsyncIeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LINE_IE` reader - Line interrupt enable"]
pub type LineIeR = crate::BitReader;
#[doc = "Field `LINE_IE` writer - Line interrupt enable"]
pub type LineIeW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Capture complete interrupt enable"]
    #[inline(always)]
    pub fn frame_ie(&self) -> FrameIeR {
        FrameIeR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Overrun interrupt enable"]
    #[inline(always)]
    pub fn ovr_ie(&self) -> OvrIeR {
        OvrIeR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Synchronization error interrupt enable"]
    #[inline(always)]
    pub fn err_ie(&self) -> ErrIeR {
        ErrIeR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - VSYNC interrupt enable"]
    #[inline(always)]
    pub fn vsync_ie(&self) -> VsyncIeR {
        VsyncIeR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Line interrupt enable"]
    #[inline(always)]
    pub fn line_ie(&self) -> LineIeR {
        LineIeR::new(((self.bits >> 4) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Capture complete interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn frame_ie(&mut self) -> FrameIeW<IerSpec> {
        FrameIeW::new(self, 0)
    }
    #[doc = "Bit 1 - Overrun interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn ovr_ie(&mut self) -> OvrIeW<IerSpec> {
        OvrIeW::new(self, 1)
    }
    #[doc = "Bit 2 - Synchronization error interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn err_ie(&mut self) -> ErrIeW<IerSpec> {
        ErrIeW::new(self, 2)
    }
    #[doc = "Bit 3 - VSYNC interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn vsync_ie(&mut self) -> VsyncIeW<IerSpec> {
        VsyncIeW::new(self, 3)
    }
    #[doc = "Bit 4 - Line interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn line_ie(&mut self) -> LineIeW<IerSpec> {
        LineIeW::new(self, 4)
    }
}
#[doc = "interrupt enable register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ier::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ier::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IerSpec;
impl crate::RegisterSpec for IerSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`ier::R`](R) reader structure"]
impl crate::Readable for IerSpec {}
#[doc = "`write(|w| ..)` method takes [`ier::W`](W) writer structure"]
impl crate::Writable for IerSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets IER to value 0"]
impl crate::Resettable for IerSpec {
    const RESET_VALUE: u32 = 0;
}
