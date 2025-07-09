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
#[doc = "Register `MMCRGUFCR` reader"]
pub type R = crate::R<MmcrgufcrSpec>;
#[doc = "Register `MMCRGUFCR` writer"]
pub type W = crate::W<MmcrgufcrSpec>;
#[doc = "Field `RGUFC` reader - RGUFC"]
pub type RgufcR = crate::FieldReader<u32>;
#[doc = "Field `RGUFC` writer - RGUFC"]
pub type RgufcW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - RGUFC"]
    #[inline(always)]
    pub fn rgufc(&self) -> RgufcR {
        RgufcR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - RGUFC"]
    #[inline(always)]
    #[must_use]
    pub fn rgufc(&mut self) -> RgufcW<MmcrgufcrSpec> {
        RgufcW::new(self, 0)
    }
}
#[doc = "MMC received good unicast frames counter register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mmcrgufcr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MmcrgufcrSpec;
impl crate::RegisterSpec for MmcrgufcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 196u64;
}
#[doc = "`read()` method returns [`mmcrgufcr::R`](R) reader structure"]
impl crate::Readable for MmcrgufcrSpec {}
#[doc = "`reset()` method sets MMCRGUFCR to value 0"]
impl crate::Resettable for MmcrgufcrSpec {
    const RESET_VALUE: u32 = 0;
}
