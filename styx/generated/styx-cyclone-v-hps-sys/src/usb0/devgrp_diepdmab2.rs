// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_diepdmab2` reader"]
pub type R = crate::R<DevgrpDiepdmab2Spec>;
#[doc = "Register `devgrp_diepdmab2` writer"]
pub type W = crate::W<DevgrpDiepdmab2Spec>;
#[doc = "Field `diepdmab2` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab2R = crate::FieldReader<u32>;
#[doc = "Field `diepdmab2` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab2W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn diepdmab2(&self) -> Diepdmab2R {
        Diepdmab2R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn diepdmab2(&mut self) -> Diepdmab2W<DevgrpDiepdmab2Spec> {
        Diepdmab2W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab2::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepdmab2Spec;
impl crate::RegisterSpec for DevgrpDiepdmab2Spec {
    type Ux = u32;
    const OFFSET: u64 = 2396u64;
}
#[doc = "`read()` method returns [`devgrp_diepdmab2::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepdmab2Spec {}
