// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_diepdmab15` reader"]
pub type R = crate::R<DevgrpDiepdmab15Spec>;
#[doc = "Register `devgrp_diepdmab15` writer"]
pub type W = crate::W<DevgrpDiepdmab15Spec>;
#[doc = "Field `diepdmab15` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab15R = crate::FieldReader<u32>;
#[doc = "Field `diepdmab15` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab15W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn diepdmab15(&self) -> Diepdmab15R {
        Diepdmab15R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn diepdmab15(&mut self) -> Diepdmab15W<DevgrpDiepdmab15Spec> {
        Diepdmab15W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab15::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepdmab15Spec;
impl crate::RegisterSpec for DevgrpDiepdmab15Spec {
    type Ux = u32;
    const OFFSET: u64 = 2812u64;
}
#[doc = "`read()` method returns [`devgrp_diepdmab15::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepdmab15Spec {}
