// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_diepdmab9` reader"]
pub type R = crate::R<DevgrpDiepdmab9Spec>;
#[doc = "Register `devgrp_diepdmab9` writer"]
pub type W = crate::W<DevgrpDiepdmab9Spec>;
#[doc = "Field `diepdmab9` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab9R = crate::FieldReader<u32>;
#[doc = "Field `diepdmab9` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab9W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn diepdmab9(&self) -> Diepdmab9R {
        Diepdmab9R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn diepdmab9(&mut self) -> Diepdmab9W<DevgrpDiepdmab9Spec> {
        Diepdmab9W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab9::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepdmab9Spec;
impl crate::RegisterSpec for DevgrpDiepdmab9Spec {
    type Ux = u32;
    const OFFSET: u64 = 2620u64;
}
#[doc = "`read()` method returns [`devgrp_diepdmab9::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepdmab9Spec {}
