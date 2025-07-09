// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_diepdmab12` reader"]
pub type R = crate::R<DevgrpDiepdmab12Spec>;
#[doc = "Register `devgrp_diepdmab12` writer"]
pub type W = crate::W<DevgrpDiepdmab12Spec>;
#[doc = "Field `diepdmab12` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab12R = crate::FieldReader<u32>;
#[doc = "Field `diepdmab12` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab12W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn diepdmab12(&self) -> Diepdmab12R {
        Diepdmab12R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn diepdmab12(&mut self) -> Diepdmab12W<DevgrpDiepdmab12Spec> {
        Diepdmab12W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab12::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepdmab12Spec;
impl crate::RegisterSpec for DevgrpDiepdmab12Spec {
    type Ux = u32;
    const OFFSET: u64 = 2716u64;
}
#[doc = "`read()` method returns [`devgrp_diepdmab12::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepdmab12Spec {}
