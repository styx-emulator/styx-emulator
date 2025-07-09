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
#[doc = "Register `txftlr` reader"]
pub type R = crate::R<TxftlrSpec>;
#[doc = "Register `txftlr` writer"]
pub type W = crate::W<TxftlrSpec>;
#[doc = "Field `tft` reader - Controls the level of entries (or below) at which the transmit FIFO controller triggers an interrupt. When the number of transmit FIFO entries is less than or equal to this value, the transmit FIFO empty interrupt is triggered."]
pub type TftR = crate::FieldReader;
#[doc = "Field `tft` writer - Controls the level of entries (or below) at which the transmit FIFO controller triggers an interrupt. When the number of transmit FIFO entries is less than or equal to this value, the transmit FIFO empty interrupt is triggered."]
pub type TftW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Controls the level of entries (or below) at which the transmit FIFO controller triggers an interrupt. When the number of transmit FIFO entries is less than or equal to this value, the transmit FIFO empty interrupt is triggered."]
    #[inline(always)]
    pub fn tft(&self) -> TftR {
        TftR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Controls the level of entries (or below) at which the transmit FIFO controller triggers an interrupt. When the number of transmit FIFO entries is less than or equal to this value, the transmit FIFO empty interrupt is triggered."]
    #[inline(always)]
    #[must_use]
    pub fn tft(&mut self) -> TftW<TxftlrSpec> {
        TftW::new(self, 0)
    }
}
#[doc = "This register controls the threshold value for the transmit FIFO memory. It is impossible to write to this register when the SPI Slave is enabled. The SPI Slave is enabled and disabled by writing to the SPIENR register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`txftlr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`txftlr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TxftlrSpec;
impl crate::RegisterSpec for TxftlrSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`txftlr::R`](R) reader structure"]
impl crate::Readable for TxftlrSpec {}
#[doc = "`write(|w| ..)` method takes [`txftlr::W`](W) writer structure"]
impl crate::Writable for TxftlrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets txftlr to value 0"]
impl crate::Resettable for TxftlrSpec {
    const RESET_VALUE: u32 = 0;
}
