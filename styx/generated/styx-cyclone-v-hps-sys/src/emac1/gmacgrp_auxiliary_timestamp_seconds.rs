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
#[doc = "Register `gmacgrp_Auxiliary_Timestamp_Seconds` reader"]
pub type R = crate::R<GmacgrpAuxiliaryTimestampSecondsSpec>;
#[doc = "Register `gmacgrp_Auxiliary_Timestamp_Seconds` writer"]
pub type W = crate::W<GmacgrpAuxiliaryTimestampSecondsSpec>;
#[doc = "Field `auxtshi` reader - Contains the higher 32 bits (Seconds field) of the auxiliary timestamp."]
pub type AuxtshiR = crate::FieldReader<u32>;
#[doc = "Field `auxtshi` writer - Contains the higher 32 bits (Seconds field) of the auxiliary timestamp."]
pub type AuxtshiW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Contains the higher 32 bits (Seconds field) of the auxiliary timestamp."]
    #[inline(always)]
    pub fn auxtshi(&self) -> AuxtshiR {
        AuxtshiR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Contains the higher 32 bits (Seconds field) of the auxiliary timestamp."]
    #[inline(always)]
    #[must_use]
    pub fn auxtshi(&mut self) -> AuxtshiW<GmacgrpAuxiliaryTimestampSecondsSpec> {
        AuxtshiW::new(self, 0)
    }
}
#[doc = "Contains the higher 32 bits (Seconds field) of the auxiliary timestamp.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_auxiliary_timestamp_seconds::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpAuxiliaryTimestampSecondsSpec;
impl crate::RegisterSpec for GmacgrpAuxiliaryTimestampSecondsSpec {
    type Ux = u32;
    const OFFSET: u64 = 1844u64;
}
#[doc = "`read()` method returns [`gmacgrp_auxiliary_timestamp_seconds::R`](R) reader structure"]
impl crate::Readable for GmacgrpAuxiliaryTimestampSecondsSpec {}
#[doc = "`reset()` method sets gmacgrp_Auxiliary_Timestamp_Seconds to value 0"]
impl crate::Resettable for GmacgrpAuxiliaryTimestampSecondsSpec {
    const RESET_VALUE: u32 = 0;
}
