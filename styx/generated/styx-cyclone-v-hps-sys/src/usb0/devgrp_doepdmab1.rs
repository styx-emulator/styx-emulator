// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_doepdmab1` reader"]
pub type R = crate::R<DevgrpDoepdmab1Spec>;
#[doc = "Register `devgrp_doepdmab1` writer"]
pub type W = crate::W<DevgrpDoepdmab1Spec>;
#[doc = "Field `doepdmab1` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab1R = crate::FieldReader<u32>;
#[doc = "Field `doepdmab1` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab1W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn doepdmab1(&self) -> Doepdmab1R {
        Doepdmab1R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn doepdmab1(&mut self) -> Doepdmab1W<DevgrpDoepdmab1Spec> {
        Doepdmab1W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab1::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoepdmab1Spec;
impl crate::RegisterSpec for DevgrpDoepdmab1Spec {
    type Ux = u32;
    const OFFSET: u64 = 2876u64;
}
#[doc = "`read()` method returns [`devgrp_doepdmab1::R`](R) reader structure"]
impl crate::Readable for DevgrpDoepdmab1Spec {}
