// SPDX-License-Identifier: BSD-2-Clause
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
