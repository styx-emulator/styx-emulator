// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dmagrp_Receive_Poll_Demand` reader"]
pub type R = crate::R<DmagrpReceivePollDemandSpec>;
#[doc = "Register `dmagrp_Receive_Poll_Demand` writer"]
pub type W = crate::W<DmagrpReceivePollDemandSpec>;
#[doc = "Field `rpd` reader - When these bits are written with any value, the DMA reads the current descriptor pointed to by Register 19 (Current Host Receive Descriptor Register). If that descriptor is not available (owned by the Host), the reception returns to the Suspended state and the Bit 7 (RU) of Register 5 (Status Register) is not asserted. If the descriptor is available, the Rx DMA returns to the active state."]
pub type RpdR = crate::FieldReader<u32>;
#[doc = "Field `rpd` writer - When these bits are written with any value, the DMA reads the current descriptor pointed to by Register 19 (Current Host Receive Descriptor Register). If that descriptor is not available (owned by the Host), the reception returns to the Suspended state and the Bit 7 (RU) of Register 5 (Status Register) is not asserted. If the descriptor is available, the Rx DMA returns to the active state."]
pub type RpdW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - When these bits are written with any value, the DMA reads the current descriptor pointed to by Register 19 (Current Host Receive Descriptor Register). If that descriptor is not available (owned by the Host), the reception returns to the Suspended state and the Bit 7 (RU) of Register 5 (Status Register) is not asserted. If the descriptor is available, the Rx DMA returns to the active state."]
    #[inline(always)]
    pub fn rpd(&self) -> RpdR {
        RpdR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - When these bits are written with any value, the DMA reads the current descriptor pointed to by Register 19 (Current Host Receive Descriptor Register). If that descriptor is not available (owned by the Host), the reception returns to the Suspended state and the Bit 7 (RU) of Register 5 (Status Register) is not asserted. If the descriptor is available, the Rx DMA returns to the active state."]
    #[inline(always)]
    #[must_use]
    pub fn rpd(&mut self) -> RpdW<DmagrpReceivePollDemandSpec> {
        RpdW::new(self, 0)
    }
}
#[doc = "The Receive Poll Demand register enables the receive DMA to check for new descriptors. This command is used to wake up the Rx DMA from the SUSPEND state. The RxDMA can go into the SUSPEND state only because of the unavailability of descriptors it owns.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_receive_poll_demand::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_receive_poll_demand::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmagrpReceivePollDemandSpec;
impl crate::RegisterSpec for DmagrpReceivePollDemandSpec {
    type Ux = u32;
    const OFFSET: u64 = 4104u64;
}
#[doc = "`read()` method returns [`dmagrp_receive_poll_demand::R`](R) reader structure"]
impl crate::Readable for DmagrpReceivePollDemandSpec {}
#[doc = "`write(|w| ..)` method takes [`dmagrp_receive_poll_demand::W`](W) writer structure"]
impl crate::Writable for DmagrpReceivePollDemandSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dmagrp_Receive_Poll_Demand to value 0"]
impl crate::Resettable for DmagrpReceivePollDemandSpec {
    const RESET_VALUE: u32 = 0;
}
