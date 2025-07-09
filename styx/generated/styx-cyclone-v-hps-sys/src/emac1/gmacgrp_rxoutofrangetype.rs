// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxoutofrangetype` reader"]
pub type R = crate::R<GmacgrpRxoutofrangetypeSpec>;
#[doc = "Register `gmacgrp_rxoutofrangetype` writer"]
pub type W = crate::W<GmacgrpRxoutofrangetypeSpec>;
#[doc = "Field `cnt` reader - Number of frames received with length field not equal to the valid frame size (greater than 1,500 but less than 1,536)"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of frames received with length field not equal to the valid frame size (greater than 1,500 but less than 1,536)"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of frames received with length field not equal to the valid frame size (greater than 1,500 but less than 1,536)"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of frames received with length field not equal to the valid frame size (greater than 1,500 but less than 1,536)"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxoutofrangetypeSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of frames received with length field not equal to the valid frame size (greater than 1,500 but less than 1,536)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxoutofrangetype::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxoutofrangetypeSpec;
impl crate::RegisterSpec for GmacgrpRxoutofrangetypeSpec {
    type Ux = u32;
    const OFFSET: u64 = 460u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxoutofrangetype::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxoutofrangetypeSpec {}
#[doc = "`reset()` method sets gmacgrp_rxoutofrangetype to value 0"]
impl crate::Resettable for GmacgrpRxoutofrangetypeSpec {
    const RESET_VALUE: u32 = 0;
}
