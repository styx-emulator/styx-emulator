// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_doepdmab8` reader"]
pub type R = crate::R<DevgrpDoepdmab8Spec>;
#[doc = "Register `devgrp_doepdmab8` writer"]
pub type W = crate::W<DevgrpDoepdmab8Spec>;
#[doc = "Field `doepdmab8` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab8R = crate::FieldReader<u32>;
#[doc = "Field `doepdmab8` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab8W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn doepdmab8(&self) -> Doepdmab8R {
        Doepdmab8R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn doepdmab8(&mut self) -> Doepdmab8W<DevgrpDoepdmab8Spec> {
        Doepdmab8W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab8::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoepdmab8Spec;
impl crate::RegisterSpec for DevgrpDoepdmab8Spec {
    type Ux = u32;
    const OFFSET: u64 = 3100u64;
}
#[doc = "`read()` method returns [`devgrp_doepdmab8::R`](R) reader structure"]
impl crate::Readable for DevgrpDoepdmab8Spec {}
