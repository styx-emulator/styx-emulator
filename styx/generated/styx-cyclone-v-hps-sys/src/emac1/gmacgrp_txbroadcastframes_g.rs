// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_txbroadcastframes_g` reader"]
pub type R = crate::R<GmacgrpTxbroadcastframesGSpec>;
#[doc = "Register `gmacgrp_txbroadcastframes_g` writer"]
pub type W = crate::W<GmacgrpTxbroadcastframesGSpec>;
#[doc = "Field `cnt` reader - Number of good broadcast frames transmitted"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good broadcast frames transmitted"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good broadcast frames transmitted"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good broadcast frames transmitted"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpTxbroadcastframesGSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good broadcast frames transmitted\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txbroadcastframes_g::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTxbroadcastframesGSpec;
impl crate::RegisterSpec for GmacgrpTxbroadcastframesGSpec {
    type Ux = u32;
    const OFFSET: u64 = 284u64;
}
#[doc = "`read()` method returns [`gmacgrp_txbroadcastframes_g::R`](R) reader structure"]
impl crate::Readable for GmacgrpTxbroadcastframesGSpec {}
#[doc = "`reset()` method sets gmacgrp_txbroadcastframes_g to value 0"]
impl crate::Resettable for GmacgrpTxbroadcastframesGSpec {
    const RESET_VALUE: u32 = 0;
}
