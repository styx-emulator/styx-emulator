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
#[doc = "Register `status_page_cnt0` reader"]
pub type R = crate::R<StatusPageCnt0Spec>;
#[doc = "Register `status_page_cnt0` writer"]
pub type W = crate::W<StatusPageCnt0Spec>;
#[doc = "Field `value` reader - Maintains a decrementing count of the number of pages in the multi-page (pipeline and copyback) command being executed."]
pub type ValueR = crate::FieldReader;
#[doc = "Field `value` writer - Maintains a decrementing count of the number of pages in the multi-page (pipeline and copyback) command being executed."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Maintains a decrementing count of the number of pages in the multi-page (pipeline and copyback) command being executed."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Maintains a decrementing count of the number of pages in the multi-page (pipeline and copyback) command being executed."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<StatusPageCnt0Spec> {
        ValueW::new(self, 0)
    }
}
#[doc = "Decrementing page count bank 0\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`status_page_cnt0::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct StatusPageCnt0Spec;
impl crate::RegisterSpec for StatusPageCnt0Spec {
    type Ux = u32;
    const OFFSET: u64 = 1072u64;
}
#[doc = "`read()` method returns [`status_page_cnt0::R`](R) reader structure"]
impl crate::Readable for StatusPageCnt0Spec {}
#[doc = "`reset()` method sets status_page_cnt0 to value 0"]
impl crate::Resettable for StatusPageCnt0Spec {
    const RESET_VALUE: u32 = 0;
}
