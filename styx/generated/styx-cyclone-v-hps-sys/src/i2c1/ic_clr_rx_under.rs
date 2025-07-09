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
#[doc = "Register `ic_clr_rx_under` reader"]
pub type R = crate::R<IcClrRxUnderSpec>;
#[doc = "Register `ic_clr_rx_under` writer"]
pub type W = crate::W<IcClrRxUnderSpec>;
#[doc = "Field `clr_rx_under` reader - Read this register to clear the RX_UNDER interrupt bit 0 of the ic_raw_intr_stat register."]
pub type ClrRxUnderR = crate::BitReader;
#[doc = "Field `clr_rx_under` writer - Read this register to clear the RX_UNDER interrupt bit 0 of the ic_raw_intr_stat register."]
pub type ClrRxUnderW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Read this register to clear the RX_UNDER interrupt bit 0 of the ic_raw_intr_stat register."]
    #[inline(always)]
    pub fn clr_rx_under(&self) -> ClrRxUnderR {
        ClrRxUnderR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Read this register to clear the RX_UNDER interrupt bit 0 of the ic_raw_intr_stat register."]
    #[inline(always)]
    #[must_use]
    pub fn clr_rx_under(&mut self) -> ClrRxUnderW<IcClrRxUnderSpec> {
        ClrRxUnderW::new(self, 0)
    }
}
#[doc = "Rx Under Interrupt Bits.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_rx_under::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcClrRxUnderSpec;
impl crate::RegisterSpec for IcClrRxUnderSpec {
    type Ux = u32;
    const OFFSET: u64 = 68u64;
}
#[doc = "`read()` method returns [`ic_clr_rx_under::R`](R) reader structure"]
impl crate::Readable for IcClrRxUnderSpec {}
#[doc = "`reset()` method sets ic_clr_rx_under to value 0"]
impl crate::Resettable for IcClrRxUnderSpec {
    const RESET_VALUE: u32 = 0;
}
