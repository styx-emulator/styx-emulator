// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rx128to255octets_gb` reader"]
pub type R = crate::R<GmacgrpRx128to255octetsGbSpec>;
#[doc = "Register `gmacgrp_rx128to255octets_gb` writer"]
pub type W = crate::W<GmacgrpRx128to255octetsGbSpec>;
#[doc = "Field `cnt` reader - Number of good and bad frames received with length between 128 and 255 (inclusive) bytes, exclusive of preamble"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good and bad frames received with length between 128 and 255 (inclusive) bytes, exclusive of preamble"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good and bad frames received with length between 128 and 255 (inclusive) bytes, exclusive of preamble"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good and bad frames received with length between 128 and 255 (inclusive) bytes, exclusive of preamble"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRx128to255octetsGbSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good and bad frames received with length between 128 and 255 (inclusive) bytes, exclusive of preamble\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rx128to255octets_gb::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRx128to255octetsGbSpec;
impl crate::RegisterSpec for GmacgrpRx128to255octetsGbSpec {
    type Ux = u32;
    const OFFSET: u64 = 436u64;
}
#[doc = "`read()` method returns [`gmacgrp_rx128to255octets_gb::R`](R) reader structure"]
impl crate::Readable for GmacgrpRx128to255octetsGbSpec {}
#[doc = "`reset()` method sets gmacgrp_rx128to255octets_gb to value 0"]
impl crate::Resettable for GmacgrpRx128to255octetsGbSpec {
    const RESET_VALUE: u32 = 0;
}
