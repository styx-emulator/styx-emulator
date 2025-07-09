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
#[doc = "Register `cp_wdt_cnt_rst` reader"]
pub type R = crate::R<CpWdtCntRstSpec>;
#[doc = "Register `cp_wdt_cnt_rst` writer"]
pub type W = crate::W<CpWdtCntRstSpec>;
#[doc = "Field `cp_wdt_cnt_rst` reader - The timeout period range is fixed. The range increments by the power of 2 from 2 to the 16 to 2 to the 31."]
pub type CpWdtCntRstR = crate::FieldReader<u32>;
#[doc = "Field `cp_wdt_cnt_rst` writer - The timeout period range is fixed. The range increments by the power of 2 from 2 to the 16 to 2 to the 31."]
pub type CpWdtCntRstW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - The timeout period range is fixed. The range increments by the power of 2 from 2 to the 16 to 2 to the 31."]
    #[inline(always)]
    pub fn cp_wdt_cnt_rst(&self) -> CpWdtCntRstR {
        CpWdtCntRstR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - The timeout period range is fixed. The range increments by the power of 2 from 2 to the 16 to 2 to the 31."]
    #[inline(always)]
    #[must_use]
    pub fn cp_wdt_cnt_rst(&mut self) -> CpWdtCntRstW<CpWdtCntRstSpec> {
        CpWdtCntRstW::new(self, 0)
    }
}
#[doc = "This is a constant read-only register that contains encoded information about the component's parameter settings.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cp_wdt_cnt_rst::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CpWdtCntRstSpec;
impl crate::RegisterSpec for CpWdtCntRstSpec {
    type Ux = u32;
    const OFFSET: u64 = 240u64;
}
#[doc = "`read()` method returns [`cp_wdt_cnt_rst::R`](R) reader structure"]
impl crate::Readable for CpWdtCntRstSpec {}
#[doc = "`reset()` method sets cp_wdt_cnt_rst to value 0x7fff_ffff"]
impl crate::Resettable for CpWdtCntRstSpec {
    const RESET_VALUE: u32 = 0x7fff_ffff;
}
