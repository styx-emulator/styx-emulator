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
#[doc = "Register `rxoicr` reader"]
pub type R = crate::R<RxoicrSpec>;
#[doc = "Register `rxoicr` writer"]
pub type W = crate::W<RxoicrSpec>;
#[doc = "Field `rxoicr` reader - This register reflects the status of the interrupt. A read from this register clears the spi_rxo_intr interrupt; writing has no effect."]
pub type RxoicrR = crate::BitReader;
#[doc = "Field `rxoicr` writer - This register reflects the status of the interrupt. A read from this register clears the spi_rxo_intr interrupt; writing has no effect."]
pub type RxoicrW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - This register reflects the status of the interrupt. A read from this register clears the spi_rxo_intr interrupt; writing has no effect."]
    #[inline(always)]
    pub fn rxoicr(&self) -> RxoicrR {
        RxoicrR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This register reflects the status of the interrupt. A read from this register clears the spi_rxo_intr interrupt; writing has no effect."]
    #[inline(always)]
    #[must_use]
    pub fn rxoicr(&mut self) -> RxoicrW<RxoicrSpec> {
        RxoicrW::new(self, 0)
    }
}
#[doc = "Receive FIFO Overflow Interrupt Clear Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rxoicr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RxoicrSpec;
impl crate::RegisterSpec for RxoicrSpec {
    type Ux = u32;
    const OFFSET: u64 = 60u64;
}
#[doc = "`read()` method returns [`rxoicr::R`](R) reader structure"]
impl crate::Readable for RxoicrSpec {}
#[doc = "`reset()` method sets rxoicr to value 0"]
impl crate::Resettable for RxoicrSpec {
    const RESET_VALUE: u32 = 0;
}
