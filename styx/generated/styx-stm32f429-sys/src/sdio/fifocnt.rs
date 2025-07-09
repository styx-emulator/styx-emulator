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
#[doc = "Register `FIFOCNT` reader"]
pub type R = crate::R<FifocntSpec>;
#[doc = "Register `FIFOCNT` writer"]
pub type W = crate::W<FifocntSpec>;
#[doc = "Field `FIFOCOUNT` reader - Remaining number of words to be written to or read from the FIFO."]
pub type FifocountR = crate::FieldReader<u32>;
#[doc = "Field `FIFOCOUNT` writer - Remaining number of words to be written to or read from the FIFO."]
pub type FifocountW<'a, REG> = crate::FieldWriter<'a, REG, 24, u32>;
impl R {
    #[doc = "Bits 0:23 - Remaining number of words to be written to or read from the FIFO."]
    #[inline(always)]
    pub fn fifocount(&self) -> FifocountR {
        FifocountR::new(self.bits & 0x00ff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:23 - Remaining number of words to be written to or read from the FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn fifocount(&mut self) -> FifocountW<FifocntSpec> {
        FifocountW::new(self, 0)
    }
}
#[doc = "FIFO counter register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fifocnt::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FifocntSpec;
impl crate::RegisterSpec for FifocntSpec {
    type Ux = u32;
    const OFFSET: u64 = 72u64;
}
#[doc = "`read()` method returns [`fifocnt::R`](R) reader structure"]
impl crate::Readable for FifocntSpec {}
#[doc = "`reset()` method sets FIFOCNT to value 0"]
impl crate::Resettable for FifocntSpec {
    const RESET_VALUE: u32 = 0;
}
