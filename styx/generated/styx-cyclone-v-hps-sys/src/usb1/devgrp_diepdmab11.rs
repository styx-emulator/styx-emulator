// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_diepdmab11` reader"]
pub type R = crate::R<DevgrpDiepdmab11Spec>;
#[doc = "Register `devgrp_diepdmab11` writer"]
pub type W = crate::W<DevgrpDiepdmab11Spec>;
#[doc = "Field `diepdmab11` reader - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab11R = crate::FieldReader<u32>;
#[doc = "Field `diepdmab11` writer - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
pub type Diepdmab11W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    pub fn diepdmab11(&self) -> Diepdmab11R {
        Diepdmab11R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode."]
    #[inline(always)]
    #[must_use]
    pub fn diepdmab11(&mut self) -> Diepdmab11W<DevgrpDiepdmab11Spec> {
        Diepdmab11W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab11::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepdmab11Spec;
impl crate::RegisterSpec for DevgrpDiepdmab11Spec {
    type Ux = u32;
    const OFFSET: u64 = 2684u64;
}
#[doc = "`read()` method returns [`devgrp_diepdmab11::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepdmab11Spec {}
