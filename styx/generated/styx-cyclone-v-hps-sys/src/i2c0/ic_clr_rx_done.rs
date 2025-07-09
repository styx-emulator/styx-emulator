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
#[doc = "Register `ic_clr_rx_done` reader"]
pub type R = crate::R<IcClrRxDoneSpec>;
#[doc = "Register `ic_clr_rx_done` writer"]
pub type W = crate::W<IcClrRxDoneSpec>;
#[doc = "Field `clr_rx_done` reader - Read this register to clear the RX_DONE interrupt (bit 7) of the ic_raw_intr_stat register."]
pub type ClrRxDoneR = crate::BitReader;
#[doc = "Field `clr_rx_done` writer - Read this register to clear the RX_DONE interrupt (bit 7) of the ic_raw_intr_stat register."]
pub type ClrRxDoneW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Read this register to clear the RX_DONE interrupt (bit 7) of the ic_raw_intr_stat register."]
    #[inline(always)]
    pub fn clr_rx_done(&self) -> ClrRxDoneR {
        ClrRxDoneR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Read this register to clear the RX_DONE interrupt (bit 7) of the ic_raw_intr_stat register."]
    #[inline(always)]
    #[must_use]
    pub fn clr_rx_done(&mut self) -> ClrRxDoneW<IcClrRxDoneSpec> {
        ClrRxDoneW::new(self, 0)
    }
}
#[doc = "Clear RX_DONE Interrupt Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_rx_done::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcClrRxDoneSpec;
impl crate::RegisterSpec for IcClrRxDoneSpec {
    type Ux = u32;
    const OFFSET: u64 = 88u64;
}
#[doc = "`read()` method returns [`ic_clr_rx_done::R`](R) reader structure"]
impl crate::Readable for IcClrRxDoneSpec {}
#[doc = "`reset()` method sets ic_clr_rx_done to value 0"]
impl crate::Resettable for IcClrRxDoneSpec {
    const RESET_VALUE: u32 = 0;
}
