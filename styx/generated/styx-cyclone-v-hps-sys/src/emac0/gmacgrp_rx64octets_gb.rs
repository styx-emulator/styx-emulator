// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rx64octets_gb` reader"]
pub type R = crate::R<GmacgrpRx64octetsGbSpec>;
#[doc = "Register `gmacgrp_rx64octets_gb` writer"]
pub type W = crate::W<GmacgrpRx64octetsGbSpec>;
#[doc = "Field `cnt` reader - Number of good and bad frames received with length 64 bytes, exclusive of preamble"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good and bad frames received with length 64 bytes, exclusive of preamble"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good and bad frames received with length 64 bytes, exclusive of preamble"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good and bad frames received with length 64 bytes, exclusive of preamble"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRx64octetsGbSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good and bad frames received with length 64 bytes, exclusive of preamble\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rx64octets_gb::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRx64octetsGbSpec;
impl crate::RegisterSpec for GmacgrpRx64octetsGbSpec {
    type Ux = u32;
    const OFFSET: u64 = 428u64;
}
#[doc = "`read()` method returns [`gmacgrp_rx64octets_gb::R`](R) reader structure"]
impl crate::Readable for GmacgrpRx64octetsGbSpec {}
#[doc = "`reset()` method sets gmacgrp_rx64octets_gb to value 0"]
impl crate::Resettable for GmacgrpRx64octetsGbSpec {
    const RESET_VALUE: u32 = 0;
}
