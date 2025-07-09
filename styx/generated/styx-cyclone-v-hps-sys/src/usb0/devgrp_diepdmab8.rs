// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_diepdmab8` reader"]
pub type R = crate::R<DevgrpDiepdmab8Spec>;
#[doc = "Register `devgrp_diepdmab8` writer"]
pub type W = crate::W<DevgrpDiepdmab8Spec>;
#[doc = "Field `diepdmab8` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab8R = crate::FieldReader<u32>;
#[doc = "Field `diepdmab8` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab8W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn diepdmab8(&self) -> Diepdmab8R {
        Diepdmab8R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn diepdmab8(&mut self) -> Diepdmab8W<DevgrpDiepdmab8Spec> {
        Diepdmab8W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab8::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepdmab8Spec;
impl crate::RegisterSpec for DevgrpDiepdmab8Spec {
    type Ux = u32;
    const OFFSET: u64 = 2588u64;
}
#[doc = "`read()` method returns [`devgrp_diepdmab8::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepdmab8Spec {}
