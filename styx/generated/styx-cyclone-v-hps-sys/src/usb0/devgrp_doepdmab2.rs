// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_doepdmab2` reader"]
pub type R = crate::R<DevgrpDoepdmab2Spec>;
#[doc = "Register `devgrp_doepdmab2` writer"]
pub type W = crate::W<DevgrpDoepdmab2Spec>;
#[doc = "Field `doepdmab2` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab2R = crate::FieldReader<u32>;
#[doc = "Field `doepdmab2` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab2W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn doepdmab2(&self) -> Doepdmab2R {
        Doepdmab2R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn doepdmab2(&mut self) -> Doepdmab2W<DevgrpDoepdmab2Spec> {
        Doepdmab2W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab2::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoepdmab2Spec;
impl crate::RegisterSpec for DevgrpDoepdmab2Spec {
    type Ux = u32;
    const OFFSET: u64 = 2908u64;
}
#[doc = "`read()` method returns [`devgrp_doepdmab2::R`](R) reader structure"]
impl crate::Readable for DevgrpDoepdmab2Spec {}
