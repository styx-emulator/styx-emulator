// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_txexcessdef` reader"]
pub type R = crate::R<GmacgrpTxexcessdefSpec>;
#[doc = "Register `gmacgrp_txexcessdef` writer"]
pub type W = crate::W<GmacgrpTxexcessdefSpec>;
#[doc = "Field `cnt` reader - Number of frames aborted due to excessive deferral error (deferred for more than two max-sized frame times)"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of frames aborted due to excessive deferral error (deferred for more than two max-sized frame times)"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of frames aborted due to excessive deferral error (deferred for more than two max-sized frame times)"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of frames aborted due to excessive deferral error (deferred for more than two max-sized frame times)"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpTxexcessdefSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of frames aborted due to excessive deferral error (deferred for more than two max-sized frame times)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txexcessdef::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTxexcessdefSpec;
impl crate::RegisterSpec for GmacgrpTxexcessdefSpec {
    type Ux = u32;
    const OFFSET: u64 = 364u64;
}
#[doc = "`read()` method returns [`gmacgrp_txexcessdef::R`](R) reader structure"]
impl crate::Readable for GmacgrpTxexcessdefSpec {}
#[doc = "`reset()` method sets gmacgrp_txexcessdef to value 0"]
impl crate::Resettable for GmacgrpTxexcessdefSpec {
    const RESET_VALUE: u32 = 0;
}
