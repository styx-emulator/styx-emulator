// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_doepdmab9` reader"]
pub type R = crate::R<DevgrpDoepdmab9Spec>;
#[doc = "Register `devgrp_doepdmab9` writer"]
pub type W = crate::W<DevgrpDoepdmab9Spec>;
#[doc = "Field `doepdmab9` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab9R = crate::FieldReader<u32>;
#[doc = "Field `doepdmab9` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab9W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn doepdmab9(&self) -> Doepdmab9R {
        Doepdmab9R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn doepdmab9(&mut self) -> Doepdmab9W<DevgrpDoepdmab9Spec> {
        Doepdmab9W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab9::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoepdmab9Spec;
impl crate::RegisterSpec for DevgrpDoepdmab9Spec {
    type Ux = u32;
    const OFFSET: u64 = 3132u64;
}
#[doc = "`read()` method returns [`devgrp_doepdmab9::R`](R) reader structure"]
impl crate::Readable for DevgrpDoepdmab9Spec {}
