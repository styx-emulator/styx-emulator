// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_doepdmab7` reader"]
pub type R = crate::R<DevgrpDoepdmab7Spec>;
#[doc = "Register `devgrp_doepdmab7` writer"]
pub type W = crate::W<DevgrpDoepdmab7Spec>;
#[doc = "Field `doepdmab7` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab7R = crate::FieldReader<u32>;
#[doc = "Field `doepdmab7` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab7W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn doepdmab7(&self) -> Doepdmab7R {
        Doepdmab7R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn doepdmab7(&mut self) -> Doepdmab7W<DevgrpDoepdmab7Spec> {
        Doepdmab7W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab7::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoepdmab7Spec;
impl crate::RegisterSpec for DevgrpDoepdmab7Spec {
    type Ux = u32;
    const OFFSET: u64 = 3068u64;
}
#[doc = "`read()` method returns [`devgrp_doepdmab7::R`](R) reader structure"]
impl crate::Readable for DevgrpDoepdmab7Spec {}
