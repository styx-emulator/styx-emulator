// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_txunderflowerror` reader"]
pub type R = crate::R<GmacgrpTxunderflowerrorSpec>;
#[doc = "Register `gmacgrp_txunderflowerror` writer"]
pub type W = crate::W<GmacgrpTxunderflowerrorSpec>;
#[doc = "Field `cnt` reader - Number of frames aborted due to frame underflow error"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of frames aborted due to frame underflow error"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of frames aborted due to frame underflow error"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of frames aborted due to frame underflow error"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpTxunderflowerrorSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of frames aborted due to frame underflow error\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txunderflowerror::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTxunderflowerrorSpec;
impl crate::RegisterSpec for GmacgrpTxunderflowerrorSpec {
    type Ux = u32;
    const OFFSET: u64 = 328u64;
}
#[doc = "`read()` method returns [`gmacgrp_txunderflowerror::R`](R) reader structure"]
impl crate::Readable for GmacgrpTxunderflowerrorSpec {}
#[doc = "`reset()` method sets gmacgrp_txunderflowerror to value 0"]
impl crate::Resettable for GmacgrpTxunderflowerrorSpec {
    const RESET_VALUE: u32 = 0;
}
