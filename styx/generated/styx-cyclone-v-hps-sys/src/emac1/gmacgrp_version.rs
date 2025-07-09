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
#[doc = "Register `gmacgrp_Version` reader"]
pub type R = crate::R<GmacgrpVersionSpec>;
#[doc = "Register `gmacgrp_Version` writer"]
pub type W = crate::W<GmacgrpVersionSpec>;
#[doc = "Field `snpsver` reader - Synopsys-defined Version (3.7)"]
pub type SnpsverR = crate::FieldReader;
#[doc = "Field `snpsver` writer - Synopsys-defined Version (3.7)"]
pub type SnpsverW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `userver` reader - Altera-defined Version"]
pub type UserverR = crate::FieldReader;
#[doc = "Field `userver` writer - Altera-defined Version"]
pub type UserverW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Synopsys-defined Version (3.7)"]
    #[inline(always)]
    pub fn snpsver(&self) -> SnpsverR {
        SnpsverR::new((self.bits & 0xff) as u8)
    }
    #[doc = "Bits 8:15 - Altera-defined Version"]
    #[inline(always)]
    pub fn userver(&self) -> UserverR {
        UserverR::new(((self.bits >> 8) & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Synopsys-defined Version (3.7)"]
    #[inline(always)]
    #[must_use]
    pub fn snpsver(&mut self) -> SnpsverW<GmacgrpVersionSpec> {
        SnpsverW::new(self, 0)
    }
    #[doc = "Bits 8:15 - Altera-defined Version"]
    #[inline(always)]
    #[must_use]
    pub fn userver(&mut self) -> UserverW<GmacgrpVersionSpec> {
        UserverW::new(self, 8)
    }
}
#[doc = "The Version registers identifies the version of the EMAC. This register contains two bytes: one specified by Synopsys to identify the core release number, and the other specified by Altera.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_version::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpVersionSpec;
impl crate::RegisterSpec for GmacgrpVersionSpec {
    type Ux = u32;
    const OFFSET: u64 = 32u64;
}
#[doc = "`read()` method returns [`gmacgrp_version::R`](R) reader structure"]
impl crate::Readable for GmacgrpVersionSpec {}
#[doc = "`reset()` method sets gmacgrp_Version to value 0x1037"]
impl crate::Resettable for GmacgrpVersionSpec {
    const RESET_VALUE: u32 = 0x1037;
}
