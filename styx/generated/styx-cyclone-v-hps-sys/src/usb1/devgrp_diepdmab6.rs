// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_diepdmab6` reader"]
pub type R = crate::R<DevgrpDiepdmab6Spec>;
#[doc = "Register `devgrp_diepdmab6` writer"]
pub type W = crate::W<DevgrpDiepdmab6Spec>;
#[doc = "Field `diepdmab6` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab6R = crate::FieldReader<u32>;
#[doc = "Field `diepdmab6` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab6W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn diepdmab6(&self) -> Diepdmab6R {
        Diepdmab6R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn diepdmab6(&mut self) -> Diepdmab6W<DevgrpDiepdmab6Spec> {
        Diepdmab6W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab6::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepdmab6Spec;
impl crate::RegisterSpec for DevgrpDiepdmab6Spec {
    type Ux = u32;
    const OFFSET: u64 = 2524u64;
}
#[doc = "`read()` method returns [`devgrp_diepdmab6::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepdmab6Spec {}
