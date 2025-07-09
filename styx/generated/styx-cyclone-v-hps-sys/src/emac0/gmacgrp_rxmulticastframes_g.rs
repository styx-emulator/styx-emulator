// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxmulticastframes_g` reader"]
pub type R = crate::R<GmacgrpRxmulticastframesGSpec>;
#[doc = "Register `gmacgrp_rxmulticastframes_g` writer"]
pub type W = crate::W<GmacgrpRxmulticastframesGSpec>;
#[doc = "Field `cnt` reader - Number of good multicast frames received"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good multicast frames received"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good multicast frames received"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good multicast frames received"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxmulticastframesGSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good multicast frames received\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxmulticastframes_g::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxmulticastframesGSpec;
impl crate::RegisterSpec for GmacgrpRxmulticastframesGSpec {
    type Ux = u32;
    const OFFSET: u64 = 400u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxmulticastframes_g::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxmulticastframesGSpec {}
#[doc = "`reset()` method sets gmacgrp_rxmulticastframes_g to value 0"]
impl crate::Resettable for GmacgrpRxmulticastframesGSpec {
    const RESET_VALUE: u32 = 0;
}
