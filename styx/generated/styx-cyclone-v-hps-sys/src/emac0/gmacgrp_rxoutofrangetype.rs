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
#[doc = "Register `gmacgrp_rxoutofrangetype` reader"]
pub type R = crate::R<GmacgrpRxoutofrangetypeSpec>;
#[doc = "Register `gmacgrp_rxoutofrangetype` writer"]
pub type W = crate::W<GmacgrpRxoutofrangetypeSpec>;
#[doc = "Field `cnt` reader - Number of frames received with length field not equal to the valid frame size (greater than 1,500 but less than 1,536)"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of frames received with length field not equal to the valid frame size (greater than 1,500 but less than 1,536)"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of frames received with length field not equal to the valid frame size (greater than 1,500 but less than 1,536)"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of frames received with length field not equal to the valid frame size (greater than 1,500 but less than 1,536)"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxoutofrangetypeSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of frames received with length field not equal to the valid frame size (greater than 1,500 but less than 1,536)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxoutofrangetype::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxoutofrangetypeSpec;
impl crate::RegisterSpec for GmacgrpRxoutofrangetypeSpec {
    type Ux = u32;
    const OFFSET: u64 = 460u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxoutofrangetype::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxoutofrangetypeSpec {}
#[doc = "`reset()` method sets gmacgrp_rxoutofrangetype to value 0"]
impl crate::Resettable for GmacgrpRxoutofrangetypeSpec {
    const RESET_VALUE: u32 = 0;
}
