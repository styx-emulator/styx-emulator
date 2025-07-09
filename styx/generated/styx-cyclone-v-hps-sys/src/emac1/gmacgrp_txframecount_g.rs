// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_txframecount_g` reader"]
pub type R = crate::R<GmacgrpTxframecountGSpec>;
#[doc = "Register `gmacgrp_txframecount_g` writer"]
pub type W = crate::W<GmacgrpTxframecountGSpec>;
#[doc = "Field `cnt` reader - Number of good frames transmitted"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good frames transmitted"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good frames transmitted"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good frames transmitted"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpTxframecountGSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good frames transmitted\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txframecount_g::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTxframecountGSpec;
impl crate::RegisterSpec for GmacgrpTxframecountGSpec {
    type Ux = u32;
    const OFFSET: u64 = 360u64;
}
#[doc = "`read()` method returns [`gmacgrp_txframecount_g::R`](R) reader structure"]
impl crate::Readable for GmacgrpTxframecountGSpec {}
#[doc = "`reset()` method sets gmacgrp_txframecount_g to value 0"]
impl crate::Resettable for GmacgrpTxframecountGSpec {
    const RESET_VALUE: u32 = 0;
}
