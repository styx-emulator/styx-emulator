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
#[doc = "Register `cp_wdt_user_top_init_max` reader"]
pub type R = crate::R<CpWdtUserTopInitMaxSpec>;
#[doc = "Register `cp_wdt_user_top_init_max` writer"]
pub type W = crate::W<CpWdtUserTopInitMaxSpec>;
#[doc = "Field `cp_wdt_user_top_init_max` reader - Upper limit of Initial Timeout Period parameters."]
pub type CpWdtUserTopInitMaxR = crate::FieldReader<u32>;
#[doc = "Field `cp_wdt_user_top_init_max` writer - Upper limit of Initial Timeout Period parameters."]
pub type CpWdtUserTopInitMaxW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Upper limit of Initial Timeout Period parameters."]
    #[inline(always)]
    pub fn cp_wdt_user_top_init_max(&self) -> CpWdtUserTopInitMaxR {
        CpWdtUserTopInitMaxR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Upper limit of Initial Timeout Period parameters."]
    #[inline(always)]
    #[must_use]
    pub fn cp_wdt_user_top_init_max(&mut self) -> CpWdtUserTopInitMaxW<CpWdtUserTopInitMaxSpec> {
        CpWdtUserTopInitMaxW::new(self, 0)
    }
}
#[doc = "This is a constant read-only register that contains encoded information about the component's parameter settings\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cp_wdt_user_top_init_max::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CpWdtUserTopInitMaxSpec;
impl crate::RegisterSpec for CpWdtUserTopInitMaxSpec {
    type Ux = u32;
    const OFFSET: u64 = 232u64;
}
#[doc = "`read()` method returns [`cp_wdt_user_top_init_max::R`](R) reader structure"]
impl crate::Readable for CpWdtUserTopInitMaxSpec {}
#[doc = "`reset()` method sets cp_wdt_user_top_init_max to value 0"]
impl crate::Resettable for CpWdtUserTopInitMaxSpec {
    const RESET_VALUE: u32 = 0;
}
