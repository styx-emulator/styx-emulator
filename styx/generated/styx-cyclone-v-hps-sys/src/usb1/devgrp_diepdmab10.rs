// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_diepdmab10` reader"]
pub type R = crate::R<DevgrpDiepdmab10Spec>;
#[doc = "Register `devgrp_diepdmab10` writer"]
pub type W = crate::W<DevgrpDiepdmab10Spec>;
#[doc = "Field `diepdmab10` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab10R = crate::FieldReader<u32>;
#[doc = "Field `diepdmab10` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab10W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn diepdmab10(&self) -> Diepdmab10R {
        Diepdmab10R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn diepdmab10(&mut self) -> Diepdmab10W<DevgrpDiepdmab10Spec> {
        Diepdmab10W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab10::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepdmab10Spec;
impl crate::RegisterSpec for DevgrpDiepdmab10Spec {
    type Ux = u32;
    const OFFSET: u64 = 2652u64;
}
#[doc = "`read()` method returns [`devgrp_diepdmab10::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepdmab10Spec {}
