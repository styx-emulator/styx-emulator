// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxpauseframes` reader"]
pub type R = crate::R<GmacgrpRxpauseframesSpec>;
#[doc = "Register `gmacgrp_rxpauseframes` writer"]
pub type W = crate::W<GmacgrpRxpauseframesSpec>;
#[doc = "Field `cnt` reader - Number of good and valid PAUSE frames received"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good and valid PAUSE frames received"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good and valid PAUSE frames received"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good and valid PAUSE frames received"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxpauseframesSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good and valid PAUSE frames received\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxpauseframes::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxpauseframesSpec;
impl crate::RegisterSpec for GmacgrpRxpauseframesSpec {
    type Ux = u32;
    const OFFSET: u64 = 464u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxpauseframes::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxpauseframesSpec {}
#[doc = "`reset()` method sets gmacgrp_rxpauseframes to value 0"]
impl crate::Resettable for GmacgrpRxpauseframesSpec {
    const RESET_VALUE: u32 = 0;
}
