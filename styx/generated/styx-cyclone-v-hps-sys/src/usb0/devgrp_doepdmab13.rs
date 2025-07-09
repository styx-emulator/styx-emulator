// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_doepdmab13` reader"]
pub type R = crate::R<DevgrpDoepdmab13Spec>;
#[doc = "Register `devgrp_doepdmab13` writer"]
pub type W = crate::W<DevgrpDoepdmab13Spec>;
#[doc = "Field `doepdmab13` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab13R = crate::FieldReader<u32>;
#[doc = "Field `doepdmab13` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab13W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn doepdmab13(&self) -> Doepdmab13R {
        Doepdmab13R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn doepdmab13(&mut self) -> Doepdmab13W<DevgrpDoepdmab13Spec> {
        Doepdmab13W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab13::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoepdmab13Spec;
impl crate::RegisterSpec for DevgrpDoepdmab13Spec {
    type Ux = u32;
    const OFFSET: u64 = 3260u64;
}
#[doc = "`read()` method returns [`devgrp_doepdmab13::R`](R) reader structure"]
impl crate::Readable for DevgrpDoepdmab13Spec {}
