// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_diepdmab4` reader"]
pub type R = crate::R<DevgrpDiepdmab4Spec>;
#[doc = "Register `devgrp_diepdmab4` writer"]
pub type W = crate::W<DevgrpDiepdmab4Spec>;
#[doc = "Field `diepdmab4` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab4R = crate::FieldReader<u32>;
#[doc = "Field `diepdmab4` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab4W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn diepdmab4(&self) -> Diepdmab4R {
        Diepdmab4R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn diepdmab4(&mut self) -> Diepdmab4W<DevgrpDiepdmab4Spec> {
        Diepdmab4W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab4::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepdmab4Spec;
impl crate::RegisterSpec for DevgrpDiepdmab4Spec {
    type Ux = u32;
    const OFFSET: u64 = 2460u64;
}
#[doc = "`read()` method returns [`devgrp_diepdmab4::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepdmab4Spec {}
