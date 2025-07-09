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
#[doc = "Register `cp_wdt_user_top_max` reader"]
pub type R = crate::R<CpWdtUserTopMaxSpec>;
#[doc = "Register `cp_wdt_user_top_max` writer"]
pub type W = crate::W<CpWdtUserTopMaxSpec>;
#[doc = "Field `cp_wdt_user_top_max` reader - Upper limit of Timeout Period parameters."]
pub type CpWdtUserTopMaxR = crate::FieldReader<u32>;
#[doc = "Field `cp_wdt_user_top_max` writer - Upper limit of Timeout Period parameters."]
pub type CpWdtUserTopMaxW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Upper limit of Timeout Period parameters."]
    #[inline(always)]
    pub fn cp_wdt_user_top_max(&self) -> CpWdtUserTopMaxR {
        CpWdtUserTopMaxR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Upper limit of Timeout Period parameters."]
    #[inline(always)]
    #[must_use]
    pub fn cp_wdt_user_top_max(&mut self) -> CpWdtUserTopMaxW<CpWdtUserTopMaxSpec> {
        CpWdtUserTopMaxW::new(self, 0)
    }
}
#[doc = "This is a constant read-only register that contains encoded information about the component's parameter settings.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cp_wdt_user_top_max::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CpWdtUserTopMaxSpec;
impl crate::RegisterSpec for CpWdtUserTopMaxSpec {
    type Ux = u32;
    const OFFSET: u64 = 228u64;
}
#[doc = "`read()` method returns [`cp_wdt_user_top_max::R`](R) reader structure"]
impl crate::Readable for CpWdtUserTopMaxSpec {}
#[doc = "`reset()` method sets cp_wdt_user_top_max to value 0"]
impl crate::Resettable for CpWdtUserTopMaxSpec {
    const RESET_VALUE: u32 = 0;
}
