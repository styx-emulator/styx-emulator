// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_tx128to255octets_gb` reader"]
pub type R = crate::R<GmacgrpTx128to255octetsGbSpec>;
#[doc = "Register `gmacgrp_tx128to255octets_gb` writer"]
pub type W = crate::W<GmacgrpTx128to255octetsGbSpec>;
#[doc = "Field `cnt` reader - Number of good and bad frames transmitted with length between 128 and 255 (inclusive) bytes, exclusive of preamble and retried frames"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good and bad frames transmitted with length between 128 and 255 (inclusive) bytes, exclusive of preamble and retried frames"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good and bad frames transmitted with length between 128 and 255 (inclusive) bytes, exclusive of preamble and retried frames"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good and bad frames transmitted with length between 128 and 255 (inclusive) bytes, exclusive of preamble and retried frames"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpTx128to255octetsGbSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good and bad frames transmitted with length between 128 and 255 (inclusive) bytes, exclusive of preamble and retried frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_tx128to255octets_gb::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTx128to255octetsGbSpec;
impl crate::RegisterSpec for GmacgrpTx128to255octetsGbSpec {
    type Ux = u32;
    const OFFSET: u64 = 300u64;
}
#[doc = "`read()` method returns [`gmacgrp_tx128to255octets_gb::R`](R) reader structure"]
impl crate::Readable for GmacgrpTx128to255octetsGbSpec {}
#[doc = "`reset()` method sets gmacgrp_tx128to255octets_gb to value 0"]
impl crate::Resettable for GmacgrpTx128to255octetsGbSpec {
    const RESET_VALUE: u32 = 0;
}
