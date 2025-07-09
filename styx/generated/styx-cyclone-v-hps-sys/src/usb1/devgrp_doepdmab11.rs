// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_doepdmab11` reader"]
pub type R = crate::R<DevgrpDoepdmab11Spec>;
#[doc = "Register `devgrp_doepdmab11` writer"]
pub type W = crate::W<DevgrpDoepdmab11Spec>;
#[doc = "Field `doepdmab11` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab11R = crate::FieldReader<u32>;
#[doc = "Field `doepdmab11` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Doepdmab11W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn doepdmab11(&self) -> Doepdmab11R {
        Doepdmab11R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn doepdmab11(&mut self) -> Doepdmab11W<DevgrpDoepdmab11Spec> {
        Doepdmab11W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab11::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoepdmab11Spec;
impl crate::RegisterSpec for DevgrpDoepdmab11Spec {
    type Ux = u32;
    const OFFSET: u64 = 3196u64;
}
#[doc = "`read()` method returns [`devgrp_doepdmab11::R`](R) reader structure"]
impl crate::Readable for DevgrpDoepdmab11Spec {}
