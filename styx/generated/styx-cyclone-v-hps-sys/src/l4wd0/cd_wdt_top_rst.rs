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
#[doc = "Register `cd_wdt_top_rst` reader"]
pub type R = crate::R<CdWdtTopRstSpec>;
#[doc = "Register `cd_wdt_top_rst` writer"]
pub type W = crate::W<CdWdtTopRstSpec>;
#[doc = "Field `cd_wdt_top_rst` reader - Contains the reset value of the WDT_TORR register."]
pub type CdWdtTopRstR = crate::FieldReader<u32>;
#[doc = "Field `cd_wdt_top_rst` writer - Contains the reset value of the WDT_TORR register."]
pub type CdWdtTopRstW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Contains the reset value of the WDT_TORR register."]
    #[inline(always)]
    pub fn cd_wdt_top_rst(&self) -> CdWdtTopRstR {
        CdWdtTopRstR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Contains the reset value of the WDT_TORR register."]
    #[inline(always)]
    #[must_use]
    pub fn cd_wdt_top_rst(&mut self) -> CdWdtTopRstW<CdWdtTopRstSpec> {
        CdWdtTopRstW::new(self, 0)
    }
}
#[doc = "This is a constant read-only register that contains encoded information about the component's parameter settings.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cd_wdt_top_rst::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CdWdtTopRstSpec;
impl crate::RegisterSpec for CdWdtTopRstSpec {
    type Ux = u32;
    const OFFSET: u64 = 236u64;
}
#[doc = "`read()` method returns [`cd_wdt_top_rst::R`](R) reader structure"]
impl crate::Readable for CdWdtTopRstSpec {}
#[doc = "`reset()` method sets cd_wdt_top_rst to value 0xff"]
impl crate::Resettable for CdWdtTopRstSpec {
    const RESET_VALUE: u32 = 0xff;
}
