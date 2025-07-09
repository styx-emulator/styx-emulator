// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_doepdmab14` reader"]
pub type R = crate::R<DevgrpDoepdmab14Spec>;
#[doc = "Register `devgrp_doepdmab14` writer"]
pub type W = crate::W<DevgrpDoepdmab14Spec>;
#[doc = "Field `doepdmab14` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab14R = crate::FieldReader<u32>;
#[doc = "Field `doepdmab14` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab14W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn doepdmab14(&self) -> Doepdmab14R {
        Doepdmab14R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn doepdmab14(&mut self) -> Doepdmab14W<DevgrpDoepdmab14Spec> {
        Doepdmab14W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab14::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoepdmab14Spec;
impl crate::RegisterSpec for DevgrpDoepdmab14Spec {
    type Ux = u32;
    const OFFSET: u64 = 3292u64;
}
#[doc = "`read()` method returns [`devgrp_doepdmab14::R`](R) reader structure"]
impl crate::Readable for DevgrpDoepdmab14Spec {}
