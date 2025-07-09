// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_txlatecol` reader"]
pub type R = crate::R<GmacgrpTxlatecolSpec>;
#[doc = "Register `gmacgrp_txlatecol` writer"]
pub type W = crate::W<GmacgrpTxlatecolSpec>;
#[doc = "Field `cnt` reader - Number of frames aborted due to late collision error"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of frames aborted due to late collision error"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of frames aborted due to late collision error"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of frames aborted due to late collision error"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpTxlatecolSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of frames aborted due to late collision error\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txlatecol::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTxlatecolSpec;
impl crate::RegisterSpec for GmacgrpTxlatecolSpec {
    type Ux = u32;
    const OFFSET: u64 = 344u64;
}
#[doc = "`read()` method returns [`gmacgrp_txlatecol::R`](R) reader structure"]
impl crate::Readable for GmacgrpTxlatecolSpec {}
#[doc = "`reset()` method sets gmacgrp_txlatecol to value 0"]
impl crate::Resettable for GmacgrpTxlatecolSpec {
    const RESET_VALUE: u32 = 0;
}
