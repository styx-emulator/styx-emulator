// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_diepdmab13` reader"]
pub type R = crate::R<DevgrpDiepdmab13Spec>;
#[doc = "Register `devgrp_diepdmab13` writer"]
pub type W = crate::W<DevgrpDiepdmab13Spec>;
#[doc = "Field `diepdmab13` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab13R = crate::FieldReader<u32>;
#[doc = "Field `diepdmab13` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab13W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn diepdmab13(&self) -> Diepdmab13R {
        Diepdmab13R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn diepdmab13(&mut self) -> Diepdmab13W<DevgrpDiepdmab13Spec> {
        Diepdmab13W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab13::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepdmab13Spec;
impl crate::RegisterSpec for DevgrpDiepdmab13Spec {
    type Ux = u32;
    const OFFSET: u64 = 2748u64;
}
#[doc = "`read()` method returns [`devgrp_diepdmab13::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepdmab13Spec {}
