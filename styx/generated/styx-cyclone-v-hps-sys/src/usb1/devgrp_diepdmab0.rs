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
#[doc = "Register `devgrp_diepdmab0` reader"]
pub type R = crate::R<DevgrpDiepdmab0Spec>;
#[doc = "Register `devgrp_diepdmab0` writer"]
pub type W = crate::W<DevgrpDiepdmab0Spec>;
#[doc = "Field `diepdmab0` reader - Used with Scatter/Gather DMA."]
pub type Diepdmab0R = crate::FieldReader<u32>;
#[doc = "Field `diepdmab0` writer - Used with Scatter/Gather DMA."]
pub type Diepdmab0W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Used with Scatter/Gather DMA."]
    #[inline(always)]
    pub fn diepdmab0(&self) -> Diepdmab0R {
        Diepdmab0R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Used with Scatter/Gather DMA."]
    #[inline(always)]
    #[must_use]
    pub fn diepdmab0(&mut self) -> Diepdmab0W<DevgrpDiepdmab0Spec> {
        Diepdmab0W::new(self, 0)
    }
}
#[doc = "Endpoint 16.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab0::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepdmab0Spec;
impl crate::RegisterSpec for DevgrpDiepdmab0Spec {
    type Ux = u32;
    const OFFSET: u64 = 2332u64;
}
#[doc = "`read()` method returns [`devgrp_diepdmab0::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepdmab0Spec {}
