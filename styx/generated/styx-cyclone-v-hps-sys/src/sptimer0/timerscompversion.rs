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
#[doc = "Register `timerscompversion` reader"]
pub type R = crate::R<TimerscompversionSpec>;
#[doc = "Register `timerscompversion` writer"]
pub type W = crate::W<TimerscompversionSpec>;
#[doc = "Field `timerscompversion` reader - Current revision number of the timers component."]
pub type TimerscompversionR = crate::FieldReader<u32>;
#[doc = "Field `timerscompversion` writer - Current revision number of the timers component."]
pub type TimerscompversionW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Current revision number of the timers component."]
    #[inline(always)]
    pub fn timerscompversion(&self) -> TimerscompversionR {
        TimerscompversionR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Current revision number of the timers component."]
    #[inline(always)]
    #[must_use]
    pub fn timerscompversion(&mut self) -> TimerscompversionW<TimerscompversionSpec> {
        TimerscompversionW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timerscompversion::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TimerscompversionSpec;
impl crate::RegisterSpec for TimerscompversionSpec {
    type Ux = u32;
    const OFFSET: u64 = 172u64;
}
#[doc = "`read()` method returns [`timerscompversion::R`](R) reader structure"]
impl crate::Readable for TimerscompversionSpec {}
#[doc = "`reset()` method sets timerscompversion to value 0x3230_352a"]
impl crate::Resettable for TimerscompversionSpec {
    const RESET_VALUE: u32 = 0x3230_352a;
}
