// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_doepdmab0` reader"]
pub type R = crate::R<DevgrpDoepdmab0Spec>;
#[doc = "Register `devgrp_doepdmab0` writer"]
pub type W = crate::W<DevgrpDoepdmab0Spec>;
#[doc = "Field `doepdmab0` reader - Used with Scatter/Gather DMA."]
pub type Doepdmab0R = crate::FieldReader<u32>;
#[doc = "Field `doepdmab0` writer - Used with Scatter/Gather DMA."]
pub type Doepdmab0W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Used with Scatter/Gather DMA."]
    #[inline(always)]
    pub fn doepdmab0(&self) -> Doepdmab0R {
        Doepdmab0R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Used with Scatter/Gather DMA."]
    #[inline(always)]
    #[must_use]
    pub fn doepdmab0(&mut self) -> Doepdmab0W<DevgrpDoepdmab0Spec> {
        Doepdmab0W::new(self, 0)
    }
}
#[doc = "DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab0::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDoepdmab0Spec;
impl crate::RegisterSpec for DevgrpDoepdmab0Spec {
    type Ux = u32;
    const OFFSET: u64 = 2844u64;
}
#[doc = "`read()` method returns [`devgrp_doepdmab0::R`](R) reader structure"]
impl crate::Readable for DevgrpDoepdmab0Spec {}
