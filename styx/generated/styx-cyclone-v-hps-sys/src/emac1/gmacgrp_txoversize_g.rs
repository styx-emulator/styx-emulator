// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_txoversize_g` reader"]
pub type R = crate::R<GmacgrpTxoversizeGSpec>;
#[doc = "Register `gmacgrp_txoversize_g` writer"]
pub type W = crate::W<GmacgrpTxoversizeGSpec>;
#[doc = "Field `cnt` reader - Number of good and bad frames received"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good and bad frames received"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good and bad frames received"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good and bad frames received"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpTxoversizeGSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good and bad frames received\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txoversize_g::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTxoversizeGSpec;
impl crate::RegisterSpec for GmacgrpTxoversizeGSpec {
    type Ux = u32;
    const OFFSET: u64 = 376u64;
}
#[doc = "`read()` method returns [`gmacgrp_txoversize_g::R`](R) reader structure"]
impl crate::Readable for GmacgrpTxoversizeGSpec {}
#[doc = "`reset()` method sets gmacgrp_txoversize_g to value 0"]
impl crate::Resettable for GmacgrpTxoversizeGSpec {
    const RESET_VALUE: u32 = 0;
}
