// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxctrlframes_g` reader"]
pub type R = crate::R<GmacgrpRxctrlframesGSpec>;
#[doc = "Register `gmacgrp_rxctrlframes_g` writer"]
pub type W = crate::W<GmacgrpRxctrlframesGSpec>;
#[doc = "Field `cnt` reader - Number of received good control frames."]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of received good control frames."]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of received good control frames."]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of received good control frames."]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxctrlframesGSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of received good control frames.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxctrlframes_g::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxctrlframesGSpec;
impl crate::RegisterSpec for GmacgrpRxctrlframesGSpec {
    type Ux = u32;
    const OFFSET: u64 = 484u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxctrlframes_g::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxctrlframesGSpec {}
#[doc = "`reset()` method sets gmacgrp_rxctrlframes_g to value 0"]
impl crate::Resettable for GmacgrpRxctrlframesGSpec {
    const RESET_VALUE: u32 = 0;
}
