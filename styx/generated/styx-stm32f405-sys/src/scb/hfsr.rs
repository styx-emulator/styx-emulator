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
#[doc = "Register `HFSR` reader"]
pub type R = crate::R<HfsrSpec>;
#[doc = "Register `HFSR` writer"]
pub type W = crate::W<HfsrSpec>;
#[doc = "Field `VECTTBL` reader - Vector table hard fault"]
pub type VecttblR = crate::BitReader;
#[doc = "Field `VECTTBL` writer - Vector table hard fault"]
pub type VecttblW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FORCED` reader - Forced hard fault"]
pub type ForcedR = crate::BitReader;
#[doc = "Field `FORCED` writer - Forced hard fault"]
pub type ForcedW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DEBUG_VT` reader - Reserved for Debug use"]
pub type DebugVtR = crate::BitReader;
#[doc = "Field `DEBUG_VT` writer - Reserved for Debug use"]
pub type DebugVtW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 1 - Vector table hard fault"]
    #[inline(always)]
    pub fn vecttbl(&self) -> VecttblR {
        VecttblR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 30 - Forced hard fault"]
    #[inline(always)]
    pub fn forced(&self) -> ForcedR {
        ForcedR::new(((self.bits >> 30) & 1) != 0)
    }
    #[doc = "Bit 31 - Reserved for Debug use"]
    #[inline(always)]
    pub fn debug_vt(&self) -> DebugVtR {
        DebugVtR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 1 - Vector table hard fault"]
    #[inline(always)]
    #[must_use]
    pub fn vecttbl(&mut self) -> VecttblW<HfsrSpec> {
        VecttblW::new(self, 1)
    }
    #[doc = "Bit 30 - Forced hard fault"]
    #[inline(always)]
    #[must_use]
    pub fn forced(&mut self) -> ForcedW<HfsrSpec> {
        ForcedW::new(self, 30)
    }
    #[doc = "Bit 31 - Reserved for Debug use"]
    #[inline(always)]
    #[must_use]
    pub fn debug_vt(&mut self) -> DebugVtW<HfsrSpec> {
        DebugVtW::new(self, 31)
    }
}
#[doc = "Hard fault status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hfsr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hfsr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HfsrSpec;
impl crate::RegisterSpec for HfsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 44u64;
}
#[doc = "`read()` method returns [`hfsr::R`](R) reader structure"]
impl crate::Readable for HfsrSpec {}
#[doc = "`write(|w| ..)` method takes [`hfsr::W`](W) writer structure"]
impl crate::Writable for HfsrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets HFSR to value 0"]
impl crate::Resettable for HfsrSpec {
    const RESET_VALUE: u32 = 0;
}
