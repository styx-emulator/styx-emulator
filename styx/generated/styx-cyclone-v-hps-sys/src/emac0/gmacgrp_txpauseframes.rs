// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_txpauseframes` reader"]
pub type R = crate::R<GmacgrpTxpauseframesSpec>;
#[doc = "Register `gmacgrp_txpauseframes` writer"]
pub type W = crate::W<GmacgrpTxpauseframesSpec>;
#[doc = "Field `cnt` reader - Number of good PAUSE frames transmitted"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good PAUSE frames transmitted"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good PAUSE frames transmitted"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good PAUSE frames transmitted"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpTxpauseframesSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good PAUSE frames transmitted\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txpauseframes::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTxpauseframesSpec;
impl crate::RegisterSpec for GmacgrpTxpauseframesSpec {
    type Ux = u32;
    const OFFSET: u64 = 368u64;
}
#[doc = "`read()` method returns [`gmacgrp_txpauseframes::R`](R) reader structure"]
impl crate::Readable for GmacgrpTxpauseframesSpec {}
#[doc = "`reset()` method sets gmacgrp_txpauseframes to value 0"]
impl crate::Resettable for GmacgrpTxpauseframesSpec {
    const RESET_VALUE: u32 = 0;
}
