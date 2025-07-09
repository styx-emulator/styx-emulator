// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxvlanframes_gb` reader"]
pub type R = crate::R<GmacgrpRxvlanframesGbSpec>;
#[doc = "Register `gmacgrp_rxvlanframes_gb` writer"]
pub type W = crate::W<GmacgrpRxvlanframesGbSpec>;
#[doc = "Field `cnt` reader - Number of good and bad VLAN frames received"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good and bad VLAN frames received"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good and bad VLAN frames received"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good and bad VLAN frames received"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxvlanframesGbSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good and bad VLAN frames received\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxvlanframes_gb::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxvlanframesGbSpec;
impl crate::RegisterSpec for GmacgrpRxvlanframesGbSpec {
    type Ux = u32;
    const OFFSET: u64 = 472u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxvlanframes_gb::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxvlanframesGbSpec {}
#[doc = "`reset()` method sets gmacgrp_rxvlanframes_gb to value 0"]
impl crate::Resettable for GmacgrpRxvlanframesGbSpec {
    const RESET_VALUE: u32 = 0;
}
