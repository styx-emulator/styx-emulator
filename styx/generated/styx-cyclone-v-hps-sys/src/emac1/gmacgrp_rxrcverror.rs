// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxrcverror` reader"]
pub type R = crate::R<GmacgrpRxrcverrorSpec>;
#[doc = "Register `gmacgrp_rxrcverror` writer"]
pub type W = crate::W<GmacgrpRxrcverrorSpec>;
#[doc = "Field `cnt` reader - Number of frames received with Receive error or Frame Extension error on the GMII or MII interface."]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of frames received with Receive error or Frame Extension error on the GMII or MII interface."]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of frames received with Receive error or Frame Extension error on the GMII or MII interface."]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of frames received with Receive error or Frame Extension error on the GMII or MII interface."]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxrcverrorSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of frames received with Receive error or Frame Extension error on the GMII or MII interface.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxrcverror::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxrcverrorSpec;
impl crate::RegisterSpec for GmacgrpRxrcverrorSpec {
    type Ux = u32;
    const OFFSET: u64 = 480u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxrcverror::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxrcverrorSpec {}
#[doc = "`reset()` method sets gmacgrp_rxrcverror to value 0"]
impl crate::Resettable for GmacgrpRxrcverrorSpec {
    const RESET_VALUE: u32 = 0;
}
