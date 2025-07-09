// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_tx1024tomaxoctets_gb` reader"]
pub type R = crate::R<GmacgrpTx1024tomaxoctetsGbSpec>;
#[doc = "Register `gmacgrp_tx1024tomaxoctets_gb` writer"]
pub type W = crate::W<GmacgrpTx1024tomaxoctetsGbSpec>;
#[doc = "Field `cnt` reader - Number of good and bad frames transmitted with length between 1,024 and maxsize (inclusive) bytes, exclusive of preamble and retried frames"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good and bad frames transmitted with length between 1,024 and maxsize (inclusive) bytes, exclusive of preamble and retried frames"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good and bad frames transmitted with length between 1,024 and maxsize (inclusive) bytes, exclusive of preamble and retried frames"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good and bad frames transmitted with length between 1,024 and maxsize (inclusive) bytes, exclusive of preamble and retried frames"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpTx1024tomaxoctetsGbSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good and bad frames transmitted with length between 1,024 and maxsize (inclusive) bytes, exclusive of preamble and retried frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_tx1024tomaxoctets_gb::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTx1024tomaxoctetsGbSpec;
impl crate::RegisterSpec for GmacgrpTx1024tomaxoctetsGbSpec {
    type Ux = u32;
    const OFFSET: u64 = 312u64;
}
#[doc = "`read()` method returns [`gmacgrp_tx1024tomaxoctets_gb::R`](R) reader structure"]
impl crate::Readable for GmacgrpTx1024tomaxoctetsGbSpec {}
#[doc = "`reset()` method sets gmacgrp_tx1024tomaxoctets_gb to value 0"]
impl crate::Resettable for GmacgrpTx1024tomaxoctetsGbSpec {
    const RESET_VALUE: u32 = 0;
}
