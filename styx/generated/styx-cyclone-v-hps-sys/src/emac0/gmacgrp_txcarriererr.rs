// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_txcarriererr` reader"]
pub type R = crate::R<GmacgrpTxcarriererrSpec>;
#[doc = "Register `gmacgrp_txcarriererr` writer"]
pub type W = crate::W<GmacgrpTxcarriererrSpec>;
#[doc = "Field `cnt` reader - Number of frames aborted due to carrier sense error (no carrier or loss of carrier)"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of frames aborted due to carrier sense error (no carrier or loss of carrier)"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of frames aborted due to carrier sense error (no carrier or loss of carrier)"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of frames aborted due to carrier sense error (no carrier or loss of carrier)"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpTxcarriererrSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of frames aborted due to carrier sense error (no carrier or loss of carrier)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txcarriererr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTxcarriererrSpec;
impl crate::RegisterSpec for GmacgrpTxcarriererrSpec {
    type Ux = u32;
    const OFFSET: u64 = 352u64;
}
#[doc = "`read()` method returns [`gmacgrp_txcarriererr::R`](R) reader structure"]
impl crate::Readable for GmacgrpTxcarriererrSpec {}
#[doc = "`reset()` method sets gmacgrp_txcarriererr to value 0"]
impl crate::Resettable for GmacgrpTxcarriererrSpec {
    const RESET_VALUE: u32 = 0;
}
