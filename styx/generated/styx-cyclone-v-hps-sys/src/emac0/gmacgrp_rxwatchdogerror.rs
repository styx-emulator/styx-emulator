// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxwatchdogerror` reader"]
pub type R = crate::R<GmacgrpRxwatchdogerrorSpec>;
#[doc = "Register `gmacgrp_rxwatchdogerror` writer"]
pub type W = crate::W<GmacgrpRxwatchdogerrorSpec>;
#[doc = "Field `cnt` reader - Number of frames received with error due to watchdog timeout error (frames with a data load larger than 2,048 bytes)"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of frames received with error due to watchdog timeout error (frames with a data load larger than 2,048 bytes)"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of frames received with error due to watchdog timeout error (frames with a data load larger than 2,048 bytes)"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of frames received with error due to watchdog timeout error (frames with a data load larger than 2,048 bytes)"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxwatchdogerrorSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of frames received with error due to watchdog timeout error (frames with a data load larger than 2,048 bytes)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxwatchdogerror::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxwatchdogerrorSpec;
impl crate::RegisterSpec for GmacgrpRxwatchdogerrorSpec {
    type Ux = u32;
    const OFFSET: u64 = 476u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxwatchdogerror::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxwatchdogerrorSpec {}
#[doc = "`reset()` method sets gmacgrp_rxwatchdogerror to value 0"]
impl crate::Resettable for GmacgrpRxwatchdogerrorSpec {
    const RESET_VALUE: u32 = 0;
}
