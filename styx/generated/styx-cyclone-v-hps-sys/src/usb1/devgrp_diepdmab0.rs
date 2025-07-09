// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `devgrp_diepdmab0` reader"]
pub type R = crate::R<DevgrpDiepdmab0Spec>;
#[doc = "Register `devgrp_diepdmab0` writer"]
pub type W = crate::W<DevgrpDiepdmab0Spec>;
#[doc = "Field `diepdmab0` reader - Used with Scatter/Gather DMA."]
pub type Diepdmab0R = crate::FieldReader<u32>;
#[doc = "Field `diepdmab0` writer - Used with Scatter/Gather DMA."]
pub type Diepdmab0W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Used with Scatter/Gather DMA."]
    #[inline(always)]
    pub fn diepdmab0(&self) -> Diepdmab0R {
        Diepdmab0R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Used with Scatter/Gather DMA."]
    #[inline(always)]
    #[must_use]
    pub fn diepdmab0(&mut self) -> Diepdmab0W<DevgrpDiepdmab0Spec> {
        Diepdmab0W::new(self, 0)
    }
}
#[doc = "Endpoint 16.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab0::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct DevgrpDiepdmab0Spec;
impl crate::RegisterSpec for DevgrpDiepdmab0Spec {
    type Ux = u32;
    const OFFSET: u64 = 2332u64;
}
#[doc = "`read()` method returns [`devgrp_diepdmab0::R`](R) reader structure"]
impl crate::Readable for DevgrpDiepdmab0Spec {}
