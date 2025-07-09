// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxunicastframes_g` reader"]
pub type R = crate::R<GmacgrpRxunicastframesGSpec>;
#[doc = "Register `gmacgrp_rxunicastframes_g` writer"]
pub type W = crate::W<GmacgrpRxunicastframesGSpec>;
#[doc = "Field `cnt` reader - Number of good unicast frames received"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good unicast frames received"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good unicast frames received"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good unicast frames received"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxunicastframesGSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good unicast frames received\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxunicastframes_g::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxunicastframesGSpec;
impl crate::RegisterSpec for GmacgrpRxunicastframesGSpec {
    type Ux = u32;
    const OFFSET: u64 = 452u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxunicastframes_g::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxunicastframesGSpec {}
#[doc = "`reset()` method sets gmacgrp_rxunicastframes_g to value 0"]
impl crate::Resettable for GmacgrpRxunicastframesGSpec {
    const RESET_VALUE: u32 = 0;
}
