// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_doepdmab12` reader"]
pub type R = crate::R<DevgrpDoepdmab12Spec>;
#[doc = "Register `devgrp_doepdmab12` writer"]
pub type W = crate::W<DevgrpDoepdmab12Spec>;
#[doc = "Field `doepdmab12` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab12R = crate::FieldReader<u32>;
#[doc = "Field `doepdmab12` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab12W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn doepdmab12(&self) -> Doepdmab12R {
        Doepdmab12R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn doepdmab12(&mut self) -> Doepdmab12W<DevgrpDoepdmab12Spec> {
        Doepdmab12W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab12::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoepdmab12Spec;
impl crate::RegisterSpec for DevgrpDoepdmab12Spec {
    type Ux = u32;
    const OFFSET: u64 = 3228u64;
}
#[doc = "`read()` method returns [`devgrp_doepdmab12::R`](R) reader structure"]
impl crate::Readable for DevgrpDoepdmab12Spec {}
