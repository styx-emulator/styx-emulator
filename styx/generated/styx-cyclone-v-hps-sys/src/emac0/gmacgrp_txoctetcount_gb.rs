// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_txoctetcount_gb` reader"]
pub type R = crate::R<GmacgrpTxoctetcountGbSpec>;
#[doc = "Register `gmacgrp_txoctetcount_gb` writer"]
pub type W = crate::W<GmacgrpTxoctetcountGbSpec>;
#[doc = "Field `cnt` reader - Number of bytes transmitted, exclusive of preamble and retried bytes, in good and bad frames"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of bytes transmitted, exclusive of preamble and retried bytes, in good and bad frames"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of bytes transmitted, exclusive of preamble and retried bytes, in good and bad frames"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of bytes transmitted, exclusive of preamble and retried bytes, in good and bad frames"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpTxoctetcountGbSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of bytes transmitted, exclusive of preamble and retried bytes, in good and bad frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txoctetcount_gb::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTxoctetcountGbSpec;
impl crate::RegisterSpec for GmacgrpTxoctetcountGbSpec {
    type Ux = u32;
    const OFFSET: u64 = 276u64;
}
#[doc = "`read()` method returns [`gmacgrp_txoctetcount_gb::R`](R) reader structure"]
impl crate::Readable for GmacgrpTxoctetcountGbSpec {}
#[doc = "`reset()` method sets gmacgrp_txoctetcount_gb to value 0"]
impl crate::Resettable for GmacgrpTxoctetcountGbSpec {
    const RESET_VALUE: u32 = 0;
}
