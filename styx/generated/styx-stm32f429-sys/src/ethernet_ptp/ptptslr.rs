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
#[doc = "Register `PTPTSLR` reader"]
pub type R = crate::R<PtptslrSpec>;
#[doc = "Register `PTPTSLR` writer"]
pub type W = crate::W<PtptslrSpec>;
#[doc = "Field `STSS` reader - STSS"]
pub type StssR = crate::FieldReader<u32>;
#[doc = "Field `STSS` writer - STSS"]
pub type StssW<'a, REG> = crate::FieldWriter<'a, REG, 31, u32>;
#[doc = "Field `STPNS` reader - STPNS"]
pub type StpnsR = crate::BitReader;
#[doc = "Field `STPNS` writer - STPNS"]
pub type StpnsW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bits 0:30 - STSS"]
    #[inline(always)]
    pub fn stss(&self) -> StssR {
        StssR::new(self.bits & 0x7fff_ffff)
    }
    #[doc = "Bit 31 - STPNS"]
    #[inline(always)]
    pub fn stpns(&self) -> StpnsR {
        StpnsR::new(((self.bits >> 31) & 1) != 0)
    }
}
impl W {
    #[doc = "Bits 0:30 - STSS"]
    #[inline(always)]
    #[must_use]
    pub fn stss(&mut self) -> StssW<PtptslrSpec> {
        StssW::new(self, 0)
    }
    #[doc = "Bit 31 - STPNS"]
    #[inline(always)]
    #[must_use]
    pub fn stpns(&mut self) -> StpnsW<PtptslrSpec> {
        StpnsW::new(self, 31)
    }
}
#[doc = "Ethernet PTP time stamp low register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ptptslr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PtptslrSpec;
impl crate::RegisterSpec for PtptslrSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`ptptslr::R`](R) reader structure"]
impl crate::Readable for PtptslrSpec {}
#[doc = "`reset()` method sets PTPTSLR to value 0"]
impl crate::Resettable for PtptslrSpec {
    const RESET_VALUE: u32 = 0;
}
