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
#[doc = "Register `rxuicr` reader"]
pub type R = crate::R<RxuicrSpec>;
#[doc = "Register `rxuicr` writer"]
pub type W = crate::W<RxuicrSpec>;
#[doc = "Field `rxuicr` reader - This register reflects the status of the interrupt. A read from this register clears the ssi_rxu_intr interrupt; writing has no effect."]
pub type RxuicrR = crate::BitReader;
#[doc = "Field `rxuicr` writer - This register reflects the status of the interrupt. A read from this register clears the ssi_rxu_intr interrupt; writing has no effect."]
pub type RxuicrW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - This register reflects the status of the interrupt. A read from this register clears the ssi_rxu_intr interrupt; writing has no effect."]
    #[inline(always)]
    pub fn rxuicr(&self) -> RxuicrR {
        RxuicrR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This register reflects the status of the interrupt. A read from this register clears the ssi_rxu_intr interrupt; writing has no effect."]
    #[inline(always)]
    #[must_use]
    pub fn rxuicr(&mut self) -> RxuicrW<RxuicrSpec> {
        RxuicrW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rxuicr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RxuicrSpec;
impl crate::RegisterSpec for RxuicrSpec {
    type Ux = u32;
    const OFFSET: u64 = 64u64;
}
#[doc = "`read()` method returns [`rxuicr::R`](R) reader structure"]
impl crate::Readable for RxuicrSpec {}
#[doc = "`reset()` method sets rxuicr to value 0"]
impl crate::Resettable for RxuicrSpec {
    const RESET_VALUE: u32 = 0;
}
