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
#[doc = "Register `siliconid2` reader"]
pub type R = crate::R<Siliconid2Spec>;
#[doc = "Register `siliconid2` writer"]
pub type W = crate::W<Siliconid2Spec>;
#[doc = "Field `rsv` reader - Reserved for future use."]
pub type RsvR = crate::FieldReader<u32>;
#[doc = "Field `rsv` writer - Reserved for future use."]
pub type RsvW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Reserved for future use."]
    #[inline(always)]
    pub fn rsv(&self) -> RsvR {
        RsvR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Reserved for future use."]
    #[inline(always)]
    #[must_use]
    pub fn rsv(&mut self) -> RsvW<Siliconid2Spec> {
        RsvW::new(self, 0)
    }
}
#[doc = "Reserved for future use.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`siliconid2::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Siliconid2Spec;
impl crate::RegisterSpec for Siliconid2Spec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`siliconid2::R`](R) reader structure"]
impl crate::Readable for Siliconid2Spec {}
#[doc = "`reset()` method sets siliconid2 to value 0"]
impl crate::Resettable for Siliconid2Spec {
    const RESET_VALUE: u32 = 0;
}
