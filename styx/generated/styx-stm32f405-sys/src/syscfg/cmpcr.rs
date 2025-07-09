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
#[doc = "Register `CMPCR` reader"]
pub type R = crate::R<CmpcrSpec>;
#[doc = "Register `CMPCR` writer"]
pub type W = crate::W<CmpcrSpec>;
#[doc = "Field `CMP_PD` reader - Compensation cell power-down"]
pub type CmpPdR = crate::BitReader;
#[doc = "Field `CMP_PD` writer - Compensation cell power-down"]
pub type CmpPdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `READY` reader - READY"]
pub type ReadyR = crate::BitReader;
#[doc = "Field `READY` writer - READY"]
pub type ReadyW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Compensation cell power-down"]
    #[inline(always)]
    pub fn cmp_pd(&self) -> CmpPdR {
        CmpPdR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 8 - READY"]
    #[inline(always)]
    pub fn ready(&self) -> ReadyR {
        ReadyR::new(((self.bits >> 8) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Compensation cell power-down"]
    #[inline(always)]
    #[must_use]
    pub fn cmp_pd(&mut self) -> CmpPdW<CmpcrSpec> {
        CmpPdW::new(self, 0)
    }
    #[doc = "Bit 8 - READY"]
    #[inline(always)]
    #[must_use]
    pub fn ready(&mut self) -> ReadyW<CmpcrSpec> {
        ReadyW::new(self, 8)
    }
}
#[doc = "Compensation cell control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cmpcr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CmpcrSpec;
impl crate::RegisterSpec for CmpcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 32u64;
}
#[doc = "`read()` method returns [`cmpcr::R`](R) reader structure"]
impl crate::Readable for CmpcrSpec {}
#[doc = "`reset()` method sets CMPCR to value 0"]
impl crate::Resettable for CmpcrSpec {
    const RESET_VALUE: u32 = 0;
}
