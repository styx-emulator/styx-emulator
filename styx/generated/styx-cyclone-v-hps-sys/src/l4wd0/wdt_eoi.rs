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
#[doc = "Register `wdt_eoi` reader"]
pub type R = crate::R<WdtEoiSpec>;
#[doc = "Register `wdt_eoi` writer"]
pub type W = crate::W<WdtEoiSpec>;
#[doc = "Field `wdt_eoi` reader - Clears the watchdog interrupt. This can be used to clear the interrupt without restarting the watchdog counter."]
pub type WdtEoiR = crate::BitReader;
#[doc = "Field `wdt_eoi` writer - Clears the watchdog interrupt. This can be used to clear the interrupt without restarting the watchdog counter."]
pub type WdtEoiW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Clears the watchdog interrupt. This can be used to clear the interrupt without restarting the watchdog counter."]
    #[inline(always)]
    pub fn wdt_eoi(&self) -> WdtEoiR {
        WdtEoiR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Clears the watchdog interrupt. This can be used to clear the interrupt without restarting the watchdog counter."]
    #[inline(always)]
    #[must_use]
    pub fn wdt_eoi(&mut self) -> WdtEoiW<WdtEoiSpec> {
        WdtEoiW::new(self, 0)
    }
}
#[doc = "Clears the watchdog interrupt when read.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wdt_eoi::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct WdtEoiSpec;
impl crate::RegisterSpec for WdtEoiSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`wdt_eoi::R`](R) reader structure"]
impl crate::Readable for WdtEoiSpec {}
#[doc = "`reset()` method sets wdt_eoi to value 0"]
impl crate::Resettable for WdtEoiSpec {
    const RESET_VALUE: u32 = 0;
}
