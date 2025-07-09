// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_tx65to127octets_gb` reader"]
pub type R = crate::R<GmacgrpTx65to127octetsGbSpec>;
#[doc = "Register `gmacgrp_tx65to127octets_gb` writer"]
pub type W = crate::W<GmacgrpTx65to127octetsGbSpec>;
#[doc = "Field `cnt` reader - Number of good and bad frames transmitted with length between 65 and 127 (inclusive) bytes, exclusive of preamble and retried frames"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good and bad frames transmitted with length between 65 and 127 (inclusive) bytes, exclusive of preamble and retried frames"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good and bad frames transmitted with length between 65 and 127 (inclusive) bytes, exclusive of preamble and retried frames"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good and bad frames transmitted with length between 65 and 127 (inclusive) bytes, exclusive of preamble and retried frames"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpTx65to127octetsGbSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good and bad frames transmitted with length between 65 and 127 (inclusive) bytes, exclusive of preamble and retried frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_tx65to127octets_gb::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTx65to127octetsGbSpec;
impl crate::RegisterSpec for GmacgrpTx65to127octetsGbSpec {
    type Ux = u32;
    const OFFSET: u64 = 296u64;
}
#[doc = "`read()` method returns [`gmacgrp_tx65to127octets_gb::R`](R) reader structure"]
impl crate::Readable for GmacgrpTx65to127octetsGbSpec {}
#[doc = "`reset()` method sets gmacgrp_tx65to127octets_gb to value 0"]
impl crate::Resettable for GmacgrpTx65to127octetsGbSpec {
    const RESET_VALUE: u32 = 0;
}
