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
#[doc = "Register `wdt_ccvr` reader"]
pub type R = crate::R<WdtCcvrSpec>;
#[doc = "Register `wdt_ccvr` writer"]
pub type W = crate::W<WdtCcvrSpec>;
#[doc = "Field `wdt_ccvr` reader - This register provides the current value of the internal counter."]
pub type WdtCcvrR = crate::FieldReader<u32>;
#[doc = "Field `wdt_ccvr` writer - This register provides the current value of the internal counter."]
pub type WdtCcvrW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This register provides the current value of the internal counter."]
    #[inline(always)]
    pub fn wdt_ccvr(&self) -> WdtCcvrR {
        WdtCcvrR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This register provides the current value of the internal counter."]
    #[inline(always)]
    #[must_use]
    pub fn wdt_ccvr(&mut self) -> WdtCcvrW<WdtCcvrSpec> {
        WdtCcvrW::new(self, 0)
    }
}
#[doc = "See Field Description\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wdt_ccvr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct WdtCcvrSpec;
impl crate::RegisterSpec for WdtCcvrSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`wdt_ccvr::R`](R) reader structure"]
impl crate::Readable for WdtCcvrSpec {}
#[doc = "`reset()` method sets wdt_ccvr to value 0x7fff_ffff"]
impl crate::Resettable for WdtCcvrSpec {
    const RESET_VALUE: u32 = 0x7fff_ffff;
}
