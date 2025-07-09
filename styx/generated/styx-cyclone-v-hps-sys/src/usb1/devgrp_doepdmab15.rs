// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_doepdmab15` reader"]
pub type R = crate::R<DevgrpDoepdmab15Spec>;
#[doc = "Register `devgrp_doepdmab15` writer"]
pub type W = crate::W<DevgrpDoepdmab15Spec>;
#[doc = "Field `doepdmab15` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab15R = crate::FieldReader<u32>;
#[doc = "Field `doepdmab15` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab15W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn doepdmab15(&self) -> Doepdmab15R {
        Doepdmab15R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn doepdmab15(&mut self) -> Doepdmab15W<DevgrpDoepdmab15Spec> {
        Doepdmab15W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab15::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoepdmab15Spec;
impl crate::RegisterSpec for DevgrpDoepdmab15Spec {
    type Ux = u32;
    const OFFSET: u64 = 3324u64;
}
#[doc = "`read()` method returns [`devgrp_doepdmab15::R`](R) reader structure"]
impl crate::Readable for DevgrpDoepdmab15Spec {}
