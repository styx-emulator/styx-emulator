// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_doepdmab3` reader"]
pub type R = crate::R<DevgrpDoepdmab3Spec>;
#[doc = "Register `devgrp_doepdmab3` writer"]
pub type W = crate::W<DevgrpDoepdmab3Spec>;
#[doc = "Field `doepdmab3` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab3R = crate::FieldReader<u32>;
#[doc = "Field `doepdmab3` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab3W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn doepdmab3(&self) -> Doepdmab3R {
        Doepdmab3R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn doepdmab3(&mut self) -> Doepdmab3W<DevgrpDoepdmab3Spec> {
        Doepdmab3W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab3::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoepdmab3Spec;
impl crate::RegisterSpec for DevgrpDoepdmab3Spec {
    type Ux = u32;
    const OFFSET: u64 = 2940u64;
}
#[doc = "`read()` method returns [`devgrp_doepdmab3::R`](R) reader structure"]
impl crate::Readable for DevgrpDoepdmab3Spec {}
