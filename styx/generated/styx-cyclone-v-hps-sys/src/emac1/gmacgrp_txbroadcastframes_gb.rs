// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_txbroadcastframes_gb` reader"]
pub type R = crate::R<GmacgrpTxbroadcastframesGbSpec>;
#[doc = "Register `gmacgrp_txbroadcastframes_gb` writer"]
pub type W = crate::W<GmacgrpTxbroadcastframesGbSpec>;
#[doc = "Field `cnt` reader - Number of good and bad broadcast frames transmitted"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good and bad broadcast frames transmitted"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good and bad broadcast frames transmitted"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good and bad broadcast frames transmitted"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpTxbroadcastframesGbSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good and bad broadcast frames transmitted\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txbroadcastframes_gb::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTxbroadcastframesGbSpec;
impl crate::RegisterSpec for GmacgrpTxbroadcastframesGbSpec {
    type Ux = u32;
    const OFFSET: u64 = 324u64;
}
#[doc = "`read()` method returns [`gmacgrp_txbroadcastframes_gb::R`](R) reader structure"]
impl crate::Readable for GmacgrpTxbroadcastframesGbSpec {}
#[doc = "`reset()` method sets gmacgrp_txbroadcastframes_gb to value 0"]
impl crate::Resettable for GmacgrpTxbroadcastframesGbSpec {
    const RESET_VALUE: u32 = 0;
}
