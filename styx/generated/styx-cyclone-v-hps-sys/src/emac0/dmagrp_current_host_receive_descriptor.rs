// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dmagrp_Current_Host_Receive_Descriptor` reader"]
pub type R = crate::R<DmagrpCurrentHostReceiveDescriptorSpec>;
#[doc = "Register `dmagrp_Current_Host_Receive_Descriptor` writer"]
pub type W = crate::W<DmagrpCurrentHostReceiveDescriptorSpec>;
#[doc = "Field `currdesaptr` reader - Cleared on Reset. Pointer updated by the DMA during operation."]
pub type CurrdesaptrR = crate::FieldReader<u32>;
#[doc = "Field `currdesaptr` writer - Cleared on Reset. Pointer updated by the DMA during operation."]
pub type CurrdesaptrW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Cleared on Reset. Pointer updated by the DMA during operation."]
    #[inline(always)]
    pub fn currdesaptr(&self) -> CurrdesaptrR {
        CurrdesaptrR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Cleared on Reset. Pointer updated by the DMA during operation."]
    #[inline(always)]
    #[must_use]
    pub fn currdesaptr(&mut self) -> CurrdesaptrW<DmagrpCurrentHostReceiveDescriptorSpec> {
        CurrdesaptrW::new(self, 0)
    }
}
#[doc = "The Current Host Receive Descriptor register points to the start address of the current Receive Descriptor read by the DMA.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_current_host_receive_descriptor::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmagrpCurrentHostReceiveDescriptorSpec;
impl crate::RegisterSpec for DmagrpCurrentHostReceiveDescriptorSpec {
    type Ux = u32;
    const OFFSET: u64 = 4172u64;
}
#[doc = "`read()` method returns [`dmagrp_current_host_receive_descriptor::R`](R) reader structure"]
impl crate::Readable for DmagrpCurrentHostReceiveDescriptorSpec {}
#[doc = "`reset()` method sets dmagrp_Current_Host_Receive_Descriptor to value 0"]
impl crate::Resettable for DmagrpCurrentHostReceiveDescriptorSpec {
    const RESET_VALUE: u32 = 0;
}
