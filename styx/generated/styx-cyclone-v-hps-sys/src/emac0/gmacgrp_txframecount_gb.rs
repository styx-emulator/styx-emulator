// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_txframecount_gb` reader"]
pub type R = crate::R<GmacgrpTxframecountGbSpec>;
#[doc = "Register `gmacgrp_txframecount_gb` writer"]
pub type W = crate::W<GmacgrpTxframecountGbSpec>;
#[doc = "Field `cnt` reader - Number of good and bad frames transmitted, exclusive of retried frames"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good and bad frames transmitted, exclusive of retried frames"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good and bad frames transmitted, exclusive of retried frames"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good and bad frames transmitted, exclusive of retried frames"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpTxframecountGbSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good and bad frames transmitted, exclusive of retried frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txframecount_gb::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTxframecountGbSpec;
impl crate::RegisterSpec for GmacgrpTxframecountGbSpec {
    type Ux = u32;
    const OFFSET: u64 = 280u64;
}
#[doc = "`read()` method returns [`gmacgrp_txframecount_gb::R`](R) reader structure"]
impl crate::Readable for GmacgrpTxframecountGbSpec {}
#[doc = "`reset()` method sets gmacgrp_txframecount_gb to value 0"]
impl crate::Resettable for GmacgrpTxframecountGbSpec {
    const RESET_VALUE: u32 = 0;
}
