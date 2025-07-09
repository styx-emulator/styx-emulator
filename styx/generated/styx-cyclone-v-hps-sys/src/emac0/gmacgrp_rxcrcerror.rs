// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxcrcerror` reader"]
pub type R = crate::R<GmacgrpRxcrcerrorSpec>;
#[doc = "Register `gmacgrp_rxcrcerror` writer"]
pub type W = crate::W<GmacgrpRxcrcerrorSpec>;
#[doc = "Field `cnt` reader - Number of frames received with CRC error"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of frames received with CRC error"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of frames received with CRC error"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of frames received with CRC error"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxcrcerrorSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of frames received with CRC error\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxcrcerror::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxcrcerrorSpec;
impl crate::RegisterSpec for GmacgrpRxcrcerrorSpec {
    type Ux = u32;
    const OFFSET: u64 = 404u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxcrcerror::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxcrcerrorSpec {}
#[doc = "`reset()` method sets gmacgrp_rxcrcerror to value 0"]
impl crate::Resettable for GmacgrpRxcrcerrorSpec {
    const RESET_VALUE: u32 = 0;
}
