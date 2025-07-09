// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_diepdmab1` reader"]
pub type R = crate::R<DevgrpDiepdmab1Spec>;
#[doc = "Register `devgrp_diepdmab1` writer"]
pub type W = crate::W<DevgrpDiepdmab1Spec>;
#[doc = "Field `diepdmab1` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab1R = crate::FieldReader<u32>;
#[doc = "Field `diepdmab1` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab1W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn diepdmab1(&self) -> Diepdmab1R {
        Diepdmab1R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn diepdmab1(&mut self) -> Diepdmab1W<DevgrpDiepdmab1Spec> {
        Diepdmab1W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab1::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepdmab1Spec;
impl crate::RegisterSpec for DevgrpDiepdmab1Spec {
    type Ux = u32;
    const OFFSET: u64 = 2364u64;
}
#[doc = "`read()` method returns [`devgrp_diepdmab1::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepdmab1Spec {}
