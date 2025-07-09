// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxalignmenterror` reader"]
pub type R = crate::R<GmacgrpRxalignmenterrorSpec>;
#[doc = "Register `gmacgrp_rxalignmenterror` writer"]
pub type W = crate::W<GmacgrpRxalignmenterrorSpec>;
#[doc = "Field `cnt` reader - Number of frames received with alignment (dribble) error. Valid only in 10/100 mode"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of frames received with alignment (dribble) error. Valid only in 10/100 mode"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of frames received with alignment (dribble) error. Valid only in 10/100 mode"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of frames received with alignment (dribble) error. Valid only in 10/100 mode"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxalignmenterrorSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of frames received with alignment (dribble) error. Valid only in 10/100 mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxalignmenterror::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxalignmenterrorSpec;
impl crate::RegisterSpec for GmacgrpRxalignmenterrorSpec {
    type Ux = u32;
    const OFFSET: u64 = 408u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxalignmenterror::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxalignmenterrorSpec {}
#[doc = "`reset()` method sets gmacgrp_rxalignmenterror to value 0"]
impl crate::Resettable for GmacgrpRxalignmenterrorSpec {
    const RESET_VALUE: u32 = 0;
}
