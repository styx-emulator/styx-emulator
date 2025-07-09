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
#[doc = "Register `tfl` reader"]
pub type R = crate::R<TflSpec>;
#[doc = "Register `tfl` writer"]
pub type W = crate::W<TflSpec>;
#[doc = "Field `tfl` reader - This indicates the number of data entries in the transmit FIFO."]
pub type TflR = crate::FieldReader;
#[doc = "Field `tfl` writer - This indicates the number of data entries in the transmit FIFO."]
pub type TflW<'a, REG> = crate::FieldWriter<'a, REG, 5>;
impl R {
    #[doc = "Bits 0:4 - This indicates the number of data entries in the transmit FIFO."]
    #[inline(always)]
    pub fn tfl(&self) -> TflR {
        TflR::new((self.bits & 0x1f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:4 - This indicates the number of data entries in the transmit FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn tfl(&mut self) -> TflW<TflSpec> {
        TflW::new(self, 0)
    }
}
#[doc = "This register is used to specify the number of data entries in the Tx FIFO. Status Bits in USR register monitor the FIFO state.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tfl::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TflSpec;
impl crate::RegisterSpec for TflSpec {
    type Ux = u32;
    const OFFSET: u64 = 128u64;
}
#[doc = "`read()` method returns [`tfl::R`](R) reader structure"]
impl crate::Readable for TflSpec {}
#[doc = "`reset()` method sets tfl to value 0"]
impl crate::Resettable for TflSpec {
    const RESET_VALUE: u32 = 0;
}
