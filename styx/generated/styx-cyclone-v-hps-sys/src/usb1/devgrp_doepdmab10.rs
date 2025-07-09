// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_doepdmab10` reader"]
pub type R = crate::R<DevgrpDoepdmab10Spec>;
#[doc = "Register `devgrp_doepdmab10` writer"]
pub type W = crate::W<DevgrpDoepdmab10Spec>;
#[doc = "Field `doepdmab10` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab10R = crate::FieldReader<u32>;
#[doc = "Field `doepdmab10` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab10W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn doepdmab10(&self) -> Doepdmab10R {
        Doepdmab10R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn doepdmab10(&mut self) -> Doepdmab10W<DevgrpDoepdmab10Spec> {
        Doepdmab10W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab10::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoepdmab10Spec;
impl crate::RegisterSpec for DevgrpDoepdmab10Spec {
    type Ux = u32;
    const OFFSET: u64 = 3164u64;
}
#[doc = "`read()` method returns [`devgrp_doepdmab10::R`](R) reader structure"]
impl crate::Readable for DevgrpDoepdmab10Spec {}
