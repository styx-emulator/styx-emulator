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
#[doc = "Register `CWSIZE` reader"]
pub type R = crate::R<CwsizeSpec>;
#[doc = "Register `CWSIZE` writer"]
pub type W = crate::W<CwsizeSpec>;
#[doc = "Field `CAPCNT` reader - Capture count"]
pub type CapcntR = crate::FieldReader<u16>;
#[doc = "Field `CAPCNT` writer - Capture count"]
pub type CapcntW<'a, REG> = crate::FieldWriter<'a, REG, 14, u16>;
#[doc = "Field `VLINE` reader - Vertical line count"]
pub type VlineR = crate::FieldReader<u16>;
#[doc = "Field `VLINE` writer - Vertical line count"]
pub type VlineW<'a, REG> = crate::FieldWriter<'a, REG, 14, u16>;
impl R {
    #[doc = "Bits 0:13 - Capture count"]
    #[inline(always)]
    pub fn capcnt(&self) -> CapcntR {
        CapcntR::new((self.bits & 0x3fff) as u16)
    }
    #[doc = "Bits 16:29 - Vertical line count"]
    #[inline(always)]
    pub fn vline(&self) -> VlineR {
        VlineR::new(((self.bits >> 16) & 0x3fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:13 - Capture count"]
    #[inline(always)]
    #[must_use]
    pub fn capcnt(&mut self) -> CapcntW<CwsizeSpec> {
        CapcntW::new(self, 0)
    }
    #[doc = "Bits 16:29 - Vertical line count"]
    #[inline(always)]
    #[must_use]
    pub fn vline(&mut self) -> VlineW<CwsizeSpec> {
        VlineW::new(self, 16)
    }
}
#[doc = "crop window size\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cwsize::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cwsize::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CwsizeSpec;
impl crate::RegisterSpec for CwsizeSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`cwsize::R`](R) reader structure"]
impl crate::Readable for CwsizeSpec {}
#[doc = "`write(|w| ..)` method takes [`cwsize::W`](W) writer structure"]
impl crate::Writable for CwsizeSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CWSIZE to value 0"]
impl crate::Resettable for CwsizeSpec {
    const RESET_VALUE: u32 = 0;
}
