// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `hostgrp_hcdmab2` reader"]
pub type R = crate::R<HostgrpHcdmab2Spec>;
#[doc = "Register `hostgrp_hcdmab2` writer"]
pub type W = crate::W<HostgrpHcdmab2Spec>;
#[doc = "Field `hcdmab2` reader - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
pub type Hcdmab2R = crate::FieldReader<u32>;
#[doc = "Field `hcdmab2` writer - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
pub type Hcdmab2W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
    #[inline(always)]
    pub fn hcdmab2(&self) -> Hcdmab2R {
        Hcdmab2R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
    #[inline(always)]
    #[must_use]
    pub fn hcdmab2(&mut self) -> Hcdmab2W<HostgrpHcdmab2Spec> {
        Hcdmab2W::new(self, 0)
    }
}
#[doc = "These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdmab2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdmab2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HostgrpHcdmab2Spec;
impl crate::RegisterSpec for HostgrpHcdmab2Spec {
    type Ux = u32;
    const OFFSET: u64 = 1368u64;
}
#[doc = "`read()` method returns [`hostgrp_hcdmab2::R`](R) reader structure"]
impl crate::Readable for HostgrpHcdmab2Spec {}
#[doc = "`write(|w| ..)` method takes [`hostgrp_hcdmab2::W`](W) writer structure"]
impl crate::Writable for HostgrpHcdmab2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets hostgrp_hcdmab2 to value 0"]
impl crate::Resettable for HostgrpHcdmab2Spec {
    const RESET_VALUE: u32 = 0;
}
