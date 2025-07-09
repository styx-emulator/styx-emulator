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
#[doc = "Register `gmacgrp_rxoversize_g` reader"]
pub type R = crate::R<GmacgrpRxoversizeGSpec>;
#[doc = "Register `gmacgrp_rxoversize_g` writer"]
pub type W = crate::W<GmacgrpRxoversizeGSpec>;
#[doc = "Field `cnt` reader - Number of frames received with length greater than the maxsize (1,518 or 1,522 for VLAN tagged frames), without errors"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of frames received with length greater than the maxsize (1,518 or 1,522 for VLAN tagged frames), without errors"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of frames received with length greater than the maxsize (1,518 or 1,522 for VLAN tagged frames), without errors"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of frames received with length greater than the maxsize (1,518 or 1,522 for VLAN tagged frames), without errors"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxoversizeGSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of frames received with length greater than the maxsize (1,518 or 1,522 for VLAN tagged frames), without errors\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxoversize_g::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxoversizeGSpec;
impl crate::RegisterSpec for GmacgrpRxoversizeGSpec {
    type Ux = u32;
    const OFFSET: u64 = 424u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxoversize_g::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxoversizeGSpec {}
#[doc = "`reset()` method sets gmacgrp_rxoversize_g to value 0"]
impl crate::Resettable for GmacgrpRxoversizeGSpec {
    const RESET_VALUE: u32 = 0;
}
