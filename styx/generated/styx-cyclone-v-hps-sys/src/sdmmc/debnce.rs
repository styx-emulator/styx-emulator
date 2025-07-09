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
#[doc = "Register `debnce` reader"]
pub type R = crate::R<DebnceSpec>;
#[doc = "Register `debnce` writer"]
pub type W = crate::W<DebnceSpec>;
#[doc = "Field `debounce_count` reader - Number of host clocks l4_mp_clk used by debounce filter logic; typical debounce time is 5-25 ms."]
pub type DebounceCountR = crate::FieldReader<u32>;
#[doc = "Field `debounce_count` writer - Number of host clocks l4_mp_clk used by debounce filter logic; typical debounce time is 5-25 ms."]
pub type DebounceCountW<'a, REG> = crate::FieldWriter<'a, REG, 24, u32>;
impl R {
    #[doc = "Bits 0:23 - Number of host clocks l4_mp_clk used by debounce filter logic; typical debounce time is 5-25 ms."]
    #[inline(always)]
    pub fn debounce_count(&self) -> DebounceCountR {
        DebounceCountR::new(self.bits & 0x00ff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:23 - Number of host clocks l4_mp_clk used by debounce filter logic; typical debounce time is 5-25 ms."]
    #[inline(always)]
    #[must_use]
    pub fn debounce_count(&mut self) -> DebounceCountW<DebnceSpec> {
        DebounceCountW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`debnce::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`debnce::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DebnceSpec;
impl crate::RegisterSpec for DebnceSpec {
    type Ux = u32;
    const OFFSET: u64 = 100u64;
}
#[doc = "`read()` method returns [`debnce::R`](R) reader structure"]
impl crate::Readable for DebnceSpec {}
#[doc = "`write(|w| ..)` method takes [`debnce::W`](W) writer structure"]
impl crate::Writable for DebnceSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets debnce to value 0x00ff_ffff"]
impl crate::Resettable for DebnceSpec {
    const RESET_VALUE: u32 = 0x00ff_ffff;
}
