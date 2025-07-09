// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxlengtherror` reader"]
pub type R = crate::R<GmacgrpRxlengtherrorSpec>;
#[doc = "Register `gmacgrp_rxlengtherror` writer"]
pub type W = crate::W<GmacgrpRxlengtherrorSpec>;
#[doc = "Field `cnt` reader - Number of frames received with length error (length type field not equal to frame size), for all frames with valid length field"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of frames received with length error (length type field not equal to frame size), for all frames with valid length field"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of frames received with length error (length type field not equal to frame size), for all frames with valid length field"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of frames received with length error (length type field not equal to frame size), for all frames with valid length field"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxlengtherrorSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of frames received with length error (length type field not equal to frame size), for all frames with valid length field\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxlengtherror::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxlengtherrorSpec;
impl crate::RegisterSpec for GmacgrpRxlengtherrorSpec {
    type Ux = u32;
    const OFFSET: u64 = 456u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxlengtherror::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxlengtherrorSpec {}
#[doc = "`reset()` method sets gmacgrp_rxlengtherror to value 0"]
impl crate::Resettable for GmacgrpRxlengtherrorSpec {
    const RESET_VALUE: u32 = 0;
}
