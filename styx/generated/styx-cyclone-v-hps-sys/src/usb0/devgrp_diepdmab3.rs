// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_diepdmab3` reader"]
pub type R = crate::R<DevgrpDiepdmab3Spec>;
#[doc = "Register `devgrp_diepdmab3` writer"]
pub type W = crate::W<DevgrpDiepdmab3Spec>;
#[doc = "Field `diepdmab3` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab3R = crate::FieldReader<u32>;
#[doc = "Field `diepdmab3` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab3W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn diepdmab3(&self) -> Diepdmab3R {
        Diepdmab3R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn diepdmab3(&mut self) -> Diepdmab3W<DevgrpDiepdmab3Spec> {
        Diepdmab3W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab3::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepdmab3Spec;
impl crate::RegisterSpec for DevgrpDiepdmab3Spec {
    type Ux = u32;
    const OFFSET: u64 = 2428u64;
}
#[doc = "`read()` method returns [`devgrp_diepdmab3::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepdmab3Spec {}
