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
#[doc = "Register `gmacgrp_rxundersize_g` reader"]
pub type R = crate::R<GmacgrpRxundersizeGSpec>;
#[doc = "Register `gmacgrp_rxundersize_g` writer"]
pub type W = crate::W<GmacgrpRxundersizeGSpec>;
#[doc = "Field `cnt` reader - Number of frames received with length less than 64 bytes, without any errors"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of frames received with length less than 64 bytes, without any errors"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of frames received with length less than 64 bytes, without any errors"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of frames received with length less than 64 bytes, without any errors"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxundersizeGSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of frames received with length less than 64 bytes, without any errors\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxundersize_g::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxundersizeGSpec;
impl crate::RegisterSpec for GmacgrpRxundersizeGSpec {
    type Ux = u32;
    const OFFSET: u64 = 420u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxundersize_g::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxundersizeGSpec {}
#[doc = "`reset()` method sets gmacgrp_rxundersize_g to value 0"]
impl crate::Resettable for GmacgrpRxundersizeGSpec {
    const RESET_VALUE: u32 = 0;
}
