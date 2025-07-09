// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_txexesscol` reader"]
pub type R = crate::R<GmacgrpTxexesscolSpec>;
#[doc = "Register `gmacgrp_txexesscol` writer"]
pub type W = crate::W<GmacgrpTxexesscolSpec>;
#[doc = "Field `cnt` reader - Number of frames aborted due to excessive (16) collision errors"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of frames aborted due to excessive (16) collision errors"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of frames aborted due to excessive (16) collision errors"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of frames aborted due to excessive (16) collision errors"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpTxexesscolSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of frames aborted due to excessive (16) collision errors\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txexesscol::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTxexesscolSpec;
impl crate::RegisterSpec for GmacgrpTxexesscolSpec {
    type Ux = u32;
    const OFFSET: u64 = 348u64;
}
#[doc = "`read()` method returns [`gmacgrp_txexesscol::R`](R) reader structure"]
impl crate::Readable for GmacgrpTxexesscolSpec {}
#[doc = "`reset()` method sets gmacgrp_txexesscol to value 0"]
impl crate::Resettable for GmacgrpTxexesscolSpec {
    const RESET_VALUE: u32 = 0;
}
