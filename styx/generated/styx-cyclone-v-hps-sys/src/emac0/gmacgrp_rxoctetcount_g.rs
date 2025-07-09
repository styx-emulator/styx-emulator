// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxoctetcount_g` reader"]
pub type R = crate::R<GmacgrpRxoctetcountGSpec>;
#[doc = "Register `gmacgrp_rxoctetcount_g` writer"]
pub type W = crate::W<GmacgrpRxoctetcountGSpec>;
#[doc = "Field `cnt` reader - Number of bytes received, exclusive of preamble, only in good frames"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of bytes received, exclusive of preamble, only in good frames"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of bytes received, exclusive of preamble, only in good frames"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of bytes received, exclusive of preamble, only in good frames"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxoctetcountGSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of bytes received, exclusive of preamble, only in good frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxoctetcount_g::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxoctetcountGSpec;
impl crate::RegisterSpec for GmacgrpRxoctetcountGSpec {
    type Ux = u32;
    const OFFSET: u64 = 392u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxoctetcount_g::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxoctetcountGSpec {}
#[doc = "`reset()` method sets gmacgrp_rxoctetcount_g to value 0"]
impl crate::Resettable for GmacgrpRxoctetcountGSpec {
    const RESET_VALUE: u32 = 0;
}
