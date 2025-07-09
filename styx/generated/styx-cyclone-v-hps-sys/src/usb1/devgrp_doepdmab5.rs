// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_doepdmab5` reader"]
pub type R = crate::R<DevgrpDoepdmab5Spec>;
#[doc = "Register `devgrp_doepdmab5` writer"]
pub type W = crate::W<DevgrpDoepdmab5Spec>;
#[doc = "Field `doepdmab5` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab5R = crate::FieldReader<u32>;
#[doc = "Field `doepdmab5` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab5W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn doepdmab5(&self) -> Doepdmab5R {
        Doepdmab5R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn doepdmab5(&mut self) -> Doepdmab5W<DevgrpDoepdmab5Spec> {
        Doepdmab5W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab5::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoepdmab5Spec;
impl crate::RegisterSpec for DevgrpDoepdmab5Spec {
    type Ux = u32;
    const OFFSET: u64 = 3004u64;
}
#[doc = "`read()` method returns [`devgrp_doepdmab5::R`](R) reader structure"]
impl crate::Readable for DevgrpDoepdmab5Spec {}
