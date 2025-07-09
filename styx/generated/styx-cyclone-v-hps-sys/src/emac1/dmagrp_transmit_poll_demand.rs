// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `dmagrp_Transmit_Poll_Demand` reader"]
pub type R = crate::R<DmagrpTransmitPollDemandSpec>;
#[doc = "Register `dmagrp_Transmit_Poll_Demand` writer"]
pub type W = crate::W<DmagrpTransmitPollDemandSpec>;
#[doc = "Field `tpd` reader - When these bits are written with any value, the DMA reads the current descriptor pointed to by Register 18 (Current Host Transmit Descriptor Register). If that descriptor is not available (owned by the Host), the transmission returns to the Suspend state and the Bit 2 (TU) of Register 5 (Status Register) is asserted. If the descriptor is available, the transmission resumes."]
pub type TpdR = crate::FieldReader<u32>;
#[doc = "Field `tpd` writer - When these bits are written with any value, the DMA reads the current descriptor pointed to by Register 18 (Current Host Transmit Descriptor Register). If that descriptor is not available (owned by the Host), the transmission returns to the Suspend state and the Bit 2 (TU) of Register 5 (Status Register) is asserted. If the descriptor is available, the transmission resumes."]
pub type TpdW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - When these bits are written with any value, the DMA reads the current descriptor pointed to by Register 18 (Current Host Transmit Descriptor Register). If that descriptor is not available (owned by the Host), the transmission returns to the Suspend state and the Bit 2 (TU) of Register 5 (Status Register) is asserted. If the descriptor is available, the transmission resumes."]
    #[inline(always)]
    pub fn tpd(&self) -> TpdR {
        TpdR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - When these bits are written with any value, the DMA reads the current descriptor pointed to by Register 18 (Current Host Transmit Descriptor Register). If that descriptor is not available (owned by the Host), the transmission returns to the Suspend state and the Bit 2 (TU) of Register 5 (Status Register) is asserted. If the descriptor is available, the transmission resumes."]
    #[inline(always)]
    #[must_use]
    pub fn tpd(&mut self) -> TpdW<DmagrpTransmitPollDemandSpec> {
        TpdW::new(self, 0)
    }
}
#[doc = "The Transmit Poll Demand register enables the Tx DMA to check whether or not the DMA owns the current descriptor. The Transmit Poll Demand command is given to wake up the Tx DMA if it is in the Suspend mode. The Tx DMA can go into the Suspend mode because of an Underflow error in a transmitted frame or the unavailability of descriptors owned by it. You can give this command anytime and the Tx DMA resets this command when it again starts fetching the current descriptor from host memory.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`dmagrp_transmit_poll_demand::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`dmagrp_transmit_poll_demand::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DmagrpTransmitPollDemandSpec;
impl crate::RegisterSpec for DmagrpTransmitPollDemandSpec {
    type Ux = u32;
    const OFFSET: u64 = 4100u64;
}
#[doc = "`read()` method returns [`dmagrp_transmit_poll_demand::R`](R) reader structure"]
impl crate::Readable for DmagrpTransmitPollDemandSpec {}
#[doc = "`write(|w| ..)` method takes [`dmagrp_transmit_poll_demand::W`](W) writer structure"]
impl crate::Writable for DmagrpTransmitPollDemandSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets dmagrp_Transmit_Poll_Demand to value 0"]
impl crate::Resettable for DmagrpTransmitPollDemandSpec {
    const RESET_VALUE: u32 = 0;
}
