// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `hostgrp_hcdmab0` reader"]
pub type R = crate::R<HostgrpHcdmab0Spec>;
#[doc = "Register `hostgrp_hcdmab0` writer"]
pub type W = crate::W<HostgrpHcdmab0Spec>;
#[doc = "Field `hcdmab0` reader - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
pub type Hcdmab0R = crate::FieldReader<u32>;
#[doc = "Field `hcdmab0` writer - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
pub type Hcdmab0W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
    #[inline(always)]
    pub fn hcdmab0(&self) -> Hcdmab0R {
        Hcdmab0R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
    #[inline(always)]
    #[must_use]
    pub fn hcdmab0(&mut self) -> Hcdmab0W<HostgrpHcdmab0Spec> {
        Hcdmab0W::new(self, 0)
    }
}
#[doc = "These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdmab0::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdmab0::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HostgrpHcdmab0Spec;
impl crate::RegisterSpec for HostgrpHcdmab0Spec {
    type Ux = u32;
    const OFFSET: u64 = 1304u64;
}
#[doc = "`read()` method returns [`hostgrp_hcdmab0::R`](R) reader structure"]
impl crate::Readable for HostgrpHcdmab0Spec {}
#[doc = "`write(|w| ..)` method takes [`hostgrp_hcdmab0::W`](W) writer structure"]
impl crate::Writable for HostgrpHcdmab0Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets hostgrp_hcdmab0 to value 0"]
impl crate::Resettable for HostgrpHcdmab0Spec {
    const RESET_VALUE: u32 = 0;
}
