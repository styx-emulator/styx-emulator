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
#[doc = "Register `wdt_comp_type` reader"]
pub type R = crate::R<WdtCompTypeSpec>;
#[doc = "Register `wdt_comp_type` writer"]
pub type W = crate::W<WdtCompTypeSpec>;
#[doc = "Field `wdt_comp_type` reader - Designware Component Type number = 0x44_57_01_20."]
pub type WdtCompTypeR = crate::FieldReader<u32>;
#[doc = "Field `wdt_comp_type` writer - Designware Component Type number = 0x44_57_01_20."]
pub type WdtCompTypeW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Designware Component Type number = 0x44_57_01_20."]
    #[inline(always)]
    pub fn wdt_comp_type(&self) -> WdtCompTypeR {
        WdtCompTypeR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Designware Component Type number = 0x44_57_01_20."]
    #[inline(always)]
    #[must_use]
    pub fn wdt_comp_type(&mut self) -> WdtCompTypeW<WdtCompTypeSpec> {
        WdtCompTypeW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wdt_comp_type::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct WdtCompTypeSpec;
impl crate::RegisterSpec for WdtCompTypeSpec {
    type Ux = u32;
    const OFFSET: u64 = 252u64;
}
#[doc = "`read()` method returns [`wdt_comp_type::R`](R) reader structure"]
impl crate::Readable for WdtCompTypeSpec {}
#[doc = "`reset()` method sets wdt_comp_type to value 0x4457_0120"]
impl crate::Resettable for WdtCompTypeSpec {
    const RESET_VALUE: u32 = 0x4457_0120;
}
