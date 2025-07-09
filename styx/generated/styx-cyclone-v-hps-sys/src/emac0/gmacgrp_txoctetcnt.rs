// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_txoctetcnt` reader"]
pub type R = crate::R<GmacgrpTxoctetcntSpec>;
#[doc = "Register `gmacgrp_txoctetcnt` writer"]
pub type W = crate::W<GmacgrpTxoctetcntSpec>;
#[doc = "Field `txoctetcount_g` reader - Number of bytes transmitted, exclusive of preamble, in good frames only"]
pub type TxoctetcountGR = crate::FieldReader<u32>;
#[doc = "Field `txoctetcount_g` writer - Number of bytes transmitted, exclusive of preamble, in good frames only"]
pub type TxoctetcountGW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of bytes transmitted, exclusive of preamble, in good frames only"]
    #[inline(always)]
    pub fn txoctetcount_g(&self) -> TxoctetcountGR {
        TxoctetcountGR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of bytes transmitted, exclusive of preamble, in good frames only"]
    #[inline(always)]
    #[must_use]
    pub fn txoctetcount_g(&mut self) -> TxoctetcountGW<GmacgrpTxoctetcntSpec> {
        TxoctetcountGW::new(self, 0)
    }
}
#[doc = "Number of bytes transmitted, exclusive of preamble, in good frames only\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txoctetcnt::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTxoctetcntSpec;
impl crate::RegisterSpec for GmacgrpTxoctetcntSpec {
    type Ux = u32;
    const OFFSET: u64 = 356u64;
}
#[doc = "`read()` method returns [`gmacgrp_txoctetcnt::R`](R) reader structure"]
impl crate::Readable for GmacgrpTxoctetcntSpec {}
#[doc = "`reset()` method sets gmacgrp_txoctetcnt to value 0"]
impl crate::Resettable for GmacgrpTxoctetcntSpec {
    const RESET_VALUE: u32 = 0;
}
