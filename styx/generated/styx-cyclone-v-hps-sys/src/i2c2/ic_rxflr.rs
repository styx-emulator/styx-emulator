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
#[doc = "Register `ic_rxflr` reader"]
pub type R = crate::R<IcRxflrSpec>;
#[doc = "Register `ic_rxflr` writer"]
pub type W = crate::W<IcRxflrSpec>;
#[doc = "Field `rxflr` reader - Receive FIFO Level. Contains the number of valid data entries in the receive FIFO."]
pub type RxflrR = crate::FieldReader;
#[doc = "Field `rxflr` writer - Receive FIFO Level. Contains the number of valid data entries in the receive FIFO."]
pub type RxflrW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
impl R {
    #[doc = "Bits 0:6 - Receive FIFO Level. Contains the number of valid data entries in the receive FIFO."]
    #[inline(always)]
    pub fn rxflr(&self) -> RxflrR {
        RxflrR::new((self.bits & 0x7f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:6 - Receive FIFO Level. Contains the number of valid data entries in the receive FIFO."]
    #[inline(always)]
    #[must_use]
    pub fn rxflr(&mut self) -> RxflrW<IcRxflrSpec> {
        RxflrW::new(self, 0)
    }
}
#[doc = "This register contains the number of valid data entries in the receive FIFO buffer. It is cleared whenever: - The I2C is disabled - Whenever there is a transmit abort caused by any of the events tracked in ic_tx_abrt_source The register increments whenever data is placed into the receive FIFO and decrements when data is taken from the receive FIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_rxflr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcRxflrSpec;
impl crate::RegisterSpec for IcRxflrSpec {
    type Ux = u32;
    const OFFSET: u64 = 120u64;
}
#[doc = "`read()` method returns [`ic_rxflr::R`](R) reader structure"]
impl crate::Readable for IcRxflrSpec {}
#[doc = "`reset()` method sets ic_rxflr to value 0"]
impl crate::Resettable for IcRxflrSpec {
    const RESET_VALUE: u32 = 0;
}
