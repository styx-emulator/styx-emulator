// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dmagrp_Current_Host_Transmit_Descriptor` reader"]
pub type R = crate::R<DmagrpCurrentHostTransmitDescriptorSpec>;
#[doc = "Register `dmagrp_Current_Host_Transmit_Descriptor` writer"]
pub type W = crate::W<DmagrpCurrentHostTransmitDescriptorSpec>;
#[doc = "Field `curtdesaptr` reader - Cleared on Reset. Pointer updated by the DMA during operation."]
pub type CurtdesaptrR = crate::FieldReader<u32>;
#[doc = "Field `curtdesaptr` writer - Cleared on Reset. Pointer updated by the DMA during operation."]
pub type CurtdesaptrW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Cleared on Reset. Pointer updated by the DMA during operation."]
    #[inline(always)]
    pub fn curtdesaptr(&self) -> CurtdesaptrR {
        CurtdesaptrR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Cleared on Reset. Pointer updated by the DMA during operation."]
    #[inline(always)]
    #[must_use]
    pub fn curtdesaptr(&mut self) -> CurtdesaptrW<DmagrpCurrentHostTransmitDescriptorSpec> {
        CurtdesaptrW::new(self, 0)
    }
}
#[doc = "The Current Host Transmit Descriptor register points to the start address of the current Transmit Descriptor read by the DMA.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_current_host_transmit_descriptor::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmagrpCurrentHostTransmitDescriptorSpec;
impl crate::RegisterSpec for DmagrpCurrentHostTransmitDescriptorSpec {
    type Ux = u32;
    const OFFSET: u64 = 4168u64;
}
#[doc = "`read()` method returns [`dmagrp_current_host_transmit_descriptor::R`](R) reader structure"]
impl crate::Readable for DmagrpCurrentHostTransmitDescriptorSpec {}
#[doc = "`reset()` method sets dmagrp_Current_Host_Transmit_Descriptor to value 0"]
impl crate::Resettable for DmagrpCurrentHostTransmitDescriptorSpec {
    const RESET_VALUE: u32 = 0;
}
