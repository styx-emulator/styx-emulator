// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxoctetcount_gb` reader"]
pub type R = crate::R<GmacgrpRxoctetcountGbSpec>;
#[doc = "Register `gmacgrp_rxoctetcount_gb` writer"]
pub type W = crate::W<GmacgrpRxoctetcountGbSpec>;
#[doc = "Field `cnt` reader - Number of bytes received, exclusive of preamble, in good and bad frames"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of bytes received, exclusive of preamble, in good and bad frames"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of bytes received, exclusive of preamble, in good and bad frames"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of bytes received, exclusive of preamble, in good and bad frames"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxoctetcountGbSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of bytes received, exclusive of preamble, in good and bad frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxoctetcount_gb::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxoctetcountGbSpec;
impl crate::RegisterSpec for GmacgrpRxoctetcountGbSpec {
    type Ux = u32;
    const OFFSET: u64 = 388u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxoctetcount_gb::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxoctetcountGbSpec {}
#[doc = "`reset()` method sets gmacgrp_rxoctetcount_gb to value 0"]
impl crate::Resettable for GmacgrpRxoctetcountGbSpec {
    const RESET_VALUE: u32 = 0;
}
