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
#[doc = "Register `dmagrp_Current_Host_Transmit_Buffer_Address` reader"]
pub type R = crate::R<DmagrpCurrentHostTransmitBufferAddressSpec>;
#[doc = "Register `dmagrp_Current_Host_Transmit_Buffer_Address` writer"]
pub type W = crate::W<DmagrpCurrentHostTransmitBufferAddressSpec>;
#[doc = "Field `curtbufaptr` reader - Cleared on Reset. Pointer updated by the DMA during operation."]
pub type CurtbufaptrR = crate::FieldReader<u32>;
#[doc = "Field `curtbufaptr` writer - Cleared on Reset. Pointer updated by the DMA during operation."]
pub type CurtbufaptrW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Cleared on Reset. Pointer updated by the DMA during operation."]
    #[inline(always)]
    pub fn curtbufaptr(&self) -> CurtbufaptrR {
        CurtbufaptrR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Cleared on Reset. Pointer updated by the DMA during operation."]
    #[inline(always)]
    #[must_use]
    pub fn curtbufaptr(&mut self) -> CurtbufaptrW<DmagrpCurrentHostTransmitBufferAddressSpec> {
        CurtbufaptrW::new(self, 0)
    }
}
#[doc = "The Current Host Transmit Buffer Address register points to the current Transmit Buffer Address being read by the DMA.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_current_host_transmit_buffer_address::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmagrpCurrentHostTransmitBufferAddressSpec;
impl crate::RegisterSpec for DmagrpCurrentHostTransmitBufferAddressSpec {
    type Ux = u32;
    const OFFSET: u64 = 4176u64;
}
#[doc = "`read()` method returns [`dmagrp_current_host_transmit_buffer_address::R`](R) reader structure"]
impl crate::Readable for DmagrpCurrentHostTransmitBufferAddressSpec {}
#[doc = "`reset()` method sets dmagrp_Current_Host_Transmit_Buffer_Address to value 0"]
impl crate::Resettable for DmagrpCurrentHostTransmitBufferAddressSpec {
    const RESET_VALUE: u32 = 0;
}
