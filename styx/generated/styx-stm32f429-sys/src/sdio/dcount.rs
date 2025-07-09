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
#[doc = "Register `DCOUNT` reader"]
pub type R = crate::R<DcountSpec>;
#[doc = "Register `DCOUNT` writer"]
pub type W = crate::W<DcountSpec>;
#[doc = "Field `DATACOUNT` reader - Data count value"]
pub type DatacountR = crate::FieldReader<u32>;
#[doc = "Field `DATACOUNT` writer - Data count value"]
pub type DatacountW<'a, REG> = crate::FieldWriter<'a, REG, 25, u32>;
impl R {
    #[doc = "Bits 0:24 - Data count value"]
    #[inline(always)]
    pub fn datacount(&self) -> DatacountR {
        DatacountR::new(self.bits & 0x01ff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:24 - Data count value"]
    #[inline(always)]
    #[must_use]
    pub fn datacount(&mut self) -> DatacountW<DcountSpec> {
        DatacountW::new(self, 0)
    }
}
#[doc = "data counter register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dcount::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DcountSpec;
impl crate::RegisterSpec for DcountSpec {
    type Ux = u32;
    const OFFSET: u64 = 48u64;
}
#[doc = "`read()` method returns [`dcount::R`](R) reader structure"]
impl crate::Readable for DcountSpec {}
#[doc = "`reset()` method sets DCOUNT to value 0"]
impl crate::Resettable for DcountSpec {
    const RESET_VALUE: u32 = 0;
}
