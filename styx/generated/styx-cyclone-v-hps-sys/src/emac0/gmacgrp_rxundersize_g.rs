// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxundersize_g` reader"]
pub type R = crate::R<GmacgrpRxundersizeGSpec>;
#[doc = "Register `gmacgrp_rxundersize_g` writer"]
pub type W = crate::W<GmacgrpRxundersizeGSpec>;
#[doc = "Field `cnt` reader - Number of frames received with length less than 64 bytes, without any errors"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of frames received with length less than 64 bytes, without any errors"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of frames received with length less than 64 bytes, without any errors"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of frames received with length less than 64 bytes, without any errors"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxundersizeGSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of frames received with length less than 64 bytes, without any errors\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxundersize_g::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxundersizeGSpec;
impl crate::RegisterSpec for GmacgrpRxundersizeGSpec {
    type Ux = u32;
    const OFFSET: u64 = 420u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxundersize_g::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxundersizeGSpec {}
#[doc = "`reset()` method sets gmacgrp_rxundersize_g to value 0"]
impl crate::Resettable for GmacgrpRxundersizeGSpec {
    const RESET_VALUE: u32 = 0;
}
