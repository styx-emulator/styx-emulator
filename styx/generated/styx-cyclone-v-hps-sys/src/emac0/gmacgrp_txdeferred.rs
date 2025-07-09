// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_txdeferred` reader"]
pub type R = crate::R<GmacgrpTxdeferredSpec>;
#[doc = "Register `gmacgrp_txdeferred` writer"]
pub type W = crate::W<GmacgrpTxdeferredSpec>;
#[doc = "Field `cnt` reader - Number of successfully transmitted frames after a deferral in Halfduplex mode"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of successfully transmitted frames after a deferral in Halfduplex mode"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of successfully transmitted frames after a deferral in Halfduplex mode"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of successfully transmitted frames after a deferral in Halfduplex mode"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpTxdeferredSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of successfully transmitted frames after a deferral in Halfduplex mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txdeferred::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTxdeferredSpec;
impl crate::RegisterSpec for GmacgrpTxdeferredSpec {
    type Ux = u32;
    const OFFSET: u64 = 340u64;
}
#[doc = "`read()` method returns [`gmacgrp_txdeferred::R`](R) reader structure"]
impl crate::Readable for GmacgrpTxdeferredSpec {}
#[doc = "`reset()` method sets gmacgrp_txdeferred to value 0"]
impl crate::Resettable for GmacgrpTxdeferredSpec {
    const RESET_VALUE: u32 = 0;
}
