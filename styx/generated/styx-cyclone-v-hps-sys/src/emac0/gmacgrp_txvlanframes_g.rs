// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_txvlanframes_g` reader"]
pub type R = crate::R<GmacgrpTxvlanframesGSpec>;
#[doc = "Register `gmacgrp_txvlanframes_g` writer"]
pub type W = crate::W<GmacgrpTxvlanframesGSpec>;
#[doc = "Field `cnt` reader - Number of good VLAN frames transmitted, exclusive of retried frames"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good VLAN frames transmitted, exclusive of retried frames"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good VLAN frames transmitted, exclusive of retried frames"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good VLAN frames transmitted, exclusive of retried frames"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpTxvlanframesGSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good VLAN frames transmitted, exclusive of retried frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txvlanframes_g::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTxvlanframesGSpec;
impl crate::RegisterSpec for GmacgrpTxvlanframesGSpec {
    type Ux = u32;
    const OFFSET: u64 = 372u64;
}
#[doc = "`read()` method returns [`gmacgrp_txvlanframes_g::R`](R) reader structure"]
impl crate::Readable for GmacgrpTxvlanframesGSpec {}
#[doc = "`reset()` method sets gmacgrp_txvlanframes_g to value 0"]
impl crate::Resettable for GmacgrpTxvlanframesGSpec {
    const RESET_VALUE: u32 = 0;
}
