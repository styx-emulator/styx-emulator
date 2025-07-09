// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_diepdmab7` reader"]
pub type R = crate::R<DevgrpDiepdmab7Spec>;
#[doc = "Register `devgrp_diepdmab7` writer"]
pub type W = crate::W<DevgrpDiepdmab7Spec>;
#[doc = "Field `diepdmab7` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab7R = crate::FieldReader<u32>;
#[doc = "Field `diepdmab7` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab7W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn diepdmab7(&self) -> Diepdmab7R {
        Diepdmab7R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn diepdmab7(&mut self) -> Diepdmab7W<DevgrpDiepdmab7Spec> {
        Diepdmab7W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab7::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepdmab7Spec;
impl crate::RegisterSpec for DevgrpDiepdmab7Spec {
    type Ux = u32;
    const OFFSET: u64 = 2556u64;
}
#[doc = "`read()` method returns [`devgrp_diepdmab7::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepdmab7Spec {}
