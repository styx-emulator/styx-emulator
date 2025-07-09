// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_diepdmab5` reader"]
pub type R = crate::R<DevgrpDiepdmab5Spec>;
#[doc = "Register `devgrp_diepdmab5` writer"]
pub type W = crate::W<DevgrpDiepdmab5Spec>;
#[doc = "Field `diepdmab5` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab5R = crate::FieldReader<u32>;
#[doc = "Field `diepdmab5` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab5W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn diepdmab5(&self) -> Diepdmab5R {
        Diepdmab5R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn diepdmab5(&mut self) -> Diepdmab5W<DevgrpDiepdmab5Spec> {
        Diepdmab5W::new(self, 0)
    }
}
#[doc = "Device IN Endpoint 1 Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab5::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepdmab5Spec;
impl crate::RegisterSpec for DevgrpDiepdmab5Spec {
    type Ux = u32;
    const OFFSET: u64 = 2492u64;
}
#[doc = "`read()` method returns [`devgrp_diepdmab5::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepdmab5Spec {}
