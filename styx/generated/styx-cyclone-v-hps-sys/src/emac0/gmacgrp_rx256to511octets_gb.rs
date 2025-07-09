// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rx256to511octets_gb` reader"]
pub type R = crate::R<GmacgrpRx256to511octetsGbSpec>;
#[doc = "Register `gmacgrp_rx256to511octets_gb` writer"]
pub type W = crate::W<GmacgrpRx256to511octetsGbSpec>;
#[doc = "Field `cnt` reader - Number of good and bad frames received with length between 256 and 511 (inclusive) bytes, exclusive of preamble"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good and bad frames received with length between 256 and 511 (inclusive) bytes, exclusive of preamble"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good and bad frames received with length between 256 and 511 (inclusive) bytes, exclusive of preamble"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good and bad frames received with length between 256 and 511 (inclusive) bytes, exclusive of preamble"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRx256to511octetsGbSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good and bad frames received with length between 256 and 511 (inclusive) bytes, exclusive of preamble\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rx256to511octets_gb::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRx256to511octetsGbSpec;
impl crate::RegisterSpec for GmacgrpRx256to511octetsGbSpec {
    type Ux = u32;
    const OFFSET: u64 = 440u64;
}
#[doc = "`read()` method returns [`gmacgrp_rx256to511octets_gb::R`](R) reader structure"]
impl crate::Readable for GmacgrpRx256to511octetsGbSpec {}
#[doc = "`reset()` method sets gmacgrp_rx256to511octets_gb to value 0"]
impl crate::Resettable for GmacgrpRx256to511octetsGbSpec {
    const RESET_VALUE: u32 = 0;
}
