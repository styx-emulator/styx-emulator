// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxrunterror` reader"]
pub type R = crate::R<GmacgrpRxrunterrorSpec>;
#[doc = "Register `gmacgrp_rxrunterror` writer"]
pub type W = crate::W<GmacgrpRxrunterrorSpec>;
#[doc = "Field `cnt` reader - Number of frames received with runt (&lt;64 bytes and CRC error) error"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of frames received with runt (&lt;64 bytes and CRC error) error"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of frames received with runt (&lt;64 bytes and CRC error) error"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of frames received with runt (&lt;64 bytes and CRC error) error"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxrunterrorSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of frames received with runt (&lt;64 bytes and CRC error) error\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxrunterror::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxrunterrorSpec;
impl crate::RegisterSpec for GmacgrpRxrunterrorSpec {
    type Ux = u32;
    const OFFSET: u64 = 412u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxrunterror::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxrunterrorSpec {}
#[doc = "`reset()` method sets gmacgrp_rxrunterror to value 0"]
impl crate::Resettable for GmacgrpRxrunterrorSpec {
    const RESET_VALUE: u32 = 0;
}
