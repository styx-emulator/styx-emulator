// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dmagrp_Current_Host_Receive_Buffer_Address` reader"]
pub type R = crate::R<DmagrpCurrentHostReceiveBufferAddressSpec>;
#[doc = "Register `dmagrp_Current_Host_Receive_Buffer_Address` writer"]
pub type W = crate::W<DmagrpCurrentHostReceiveBufferAddressSpec>;
#[doc = "Field `currbufaptr` reader - Cleared on Reset. Pointer updated by the DMA during operation."]
pub type CurrbufaptrR = crate::FieldReader<u32>;
#[doc = "Field `currbufaptr` writer - Cleared on Reset. Pointer updated by the DMA during operation."]
pub type CurrbufaptrW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Cleared on Reset. Pointer updated by the DMA during operation."]
    #[inline(always)]
    pub fn currbufaptr(&self) -> CurrbufaptrR {
        CurrbufaptrR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Cleared on Reset. Pointer updated by the DMA during operation."]
    #[inline(always)]
    #[must_use]
    pub fn currbufaptr(&mut self) -> CurrbufaptrW<DmagrpCurrentHostReceiveBufferAddressSpec> {
        CurrbufaptrW::new(self, 0)
    }
}
#[doc = "The Current Host Receive Buffer Address register points to the current Receive Buffer address being read by the DMA.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_current_host_receive_buffer_address::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmagrpCurrentHostReceiveBufferAddressSpec;
impl crate::RegisterSpec for DmagrpCurrentHostReceiveBufferAddressSpec {
    type Ux = u32;
    const OFFSET: u64 = 4180u64;
}
#[doc = "`read()` method returns [`dmagrp_current_host_receive_buffer_address::R`](R) reader structure"]
impl crate::Readable for DmagrpCurrentHostReceiveBufferAddressSpec {}
#[doc = "`reset()` method sets dmagrp_Current_Host_Receive_Buffer_Address to value 0"]
impl crate::Resettable for DmagrpCurrentHostReceiveBufferAddressSpec {
    const RESET_VALUE: u32 = 0;
}
