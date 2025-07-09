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
#[doc = "Register `gmacgrp_rxicmp_err_octets` reader"]
pub type R = crate::R<GmacgrpRxicmpErrOctetsSpec>;
#[doc = "Register `gmacgrp_rxicmp_err_octets` writer"]
pub type W = crate::W<GmacgrpRxicmpErrOctetsSpec>;
#[doc = "Field `cnt` reader - Number of bytes received in an ICMP segment with checksum errors"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of bytes received in an ICMP segment with checksum errors"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of bytes received in an ICMP segment with checksum errors"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of bytes received in an ICMP segment with checksum errors"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxicmpErrOctetsSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of bytes received in an ICMP segment with checksum errors\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxicmp_err_octets::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxicmpErrOctetsSpec;
impl crate::RegisterSpec for GmacgrpRxicmpErrOctetsSpec {
    type Ux = u32;
    const OFFSET: u64 = 644u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxicmp_err_octets::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxicmpErrOctetsSpec {}
#[doc = "`reset()` method sets gmacgrp_rxicmp_err_octets to value 0"]
impl crate::Resettable for GmacgrpRxicmpErrOctetsSpec {
    const RESET_VALUE: u32 = 0;
}
