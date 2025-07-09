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
#[doc = "Register `timer1eoi` reader"]
pub type R = crate::R<Timer1eoiSpec>;
#[doc = "Register `timer1eoi` writer"]
pub type W = crate::W<Timer1eoiSpec>;
#[doc = "Field `timer1eoi` reader - Reading from this register clears the interrupt from Timer1 and returns 0."]
pub type Timer1eoiR = crate::BitReader;
#[doc = "Field `timer1eoi` writer - Reading from this register clears the interrupt from Timer1 and returns 0."]
pub type Timer1eoiW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Reading from this register clears the interrupt from Timer1 and returns 0."]
    #[inline(always)]
    pub fn timer1eoi(&self) -> Timer1eoiR {
        Timer1eoiR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Reading from this register clears the interrupt from Timer1 and returns 0."]
    #[inline(always)]
    #[must_use]
    pub fn timer1eoi(&mut self) -> Timer1eoiW<Timer1eoiSpec> {
        Timer1eoiW::new(self, 0)
    }
}
#[doc = "Clears Timer1 interrupt when read.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`timer1eoi::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Timer1eoiSpec;
impl crate::RegisterSpec for Timer1eoiSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`timer1eoi::R`](R) reader structure"]
impl crate::Readable for Timer1eoiSpec {}
#[doc = "`reset()` method sets timer1eoi to value 0"]
impl crate::Resettable for Timer1eoiSpec {
    const RESET_VALUE: u32 = 0;
}
