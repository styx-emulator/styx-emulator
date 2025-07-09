// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_doepdmab6` reader"]
pub type R = crate::R<DevgrpDoepdmab6Spec>;
#[doc = "Register `devgrp_doepdmab6` writer"]
pub type W = crate::W<DevgrpDoepdmab6Spec>;
#[doc = "Field `doepdmab6` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab6R = crate::FieldReader<u32>;
#[doc = "Field `doepdmab6` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab6W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn doepdmab6(&self) -> Doepdmab6R {
        Doepdmab6R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn doepdmab6(&mut self) -> Doepdmab6W<DevgrpDoepdmab6Spec> {
        Doepdmab6W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab6::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoepdmab6Spec;
impl crate::RegisterSpec for DevgrpDoepdmab6Spec {
    type Ux = u32;
    const OFFSET: u64 = 3036u64;
}
#[doc = "`read()` method returns [`devgrp_doepdmab6::R`](R) reader structure"]
impl crate::Readable for DevgrpDoepdmab6Spec {}
