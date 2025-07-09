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
#[doc = "Register `idgrp_comp_id_2` reader"]
pub type R = crate::R<IdgrpCompId2Spec>;
#[doc = "Register `idgrp_comp_id_2` writer"]
pub type W = crate::W<IdgrpCompId2Spec>;
#[doc = "Field `preamble` reader - Preamble"]
pub type PreambleR = crate::FieldReader;
#[doc = "Field `preamble` writer - Preamble"]
pub type PreambleW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Preamble"]
    #[inline(always)]
    pub fn preamble(&self) -> PreambleR {
        PreambleR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Preamble"]
    #[inline(always)]
    #[must_use]
    pub fn preamble(&mut self) -> PreambleW<IdgrpCompId2Spec> {
        PreambleW::new(self, 0)
    }
}
#[doc = "Component ID2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idgrp_comp_id_2::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IdgrpCompId2Spec;
impl crate::RegisterSpec for IdgrpCompId2Spec {
    type Ux = u32;
    const OFFSET: u64 = 8184u64;
}
#[doc = "`read()` method returns [`idgrp_comp_id_2::R`](R) reader structure"]
impl crate::Readable for IdgrpCompId2Spec {}
#[doc = "`reset()` method sets idgrp_comp_id_2 to value 0x05"]
impl crate::Resettable for IdgrpCompId2Spec {
    const RESET_VALUE: u32 = 0x05;
}
