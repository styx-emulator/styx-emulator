// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_txmulticastframes_gb` reader"]
pub type R = crate::R<GmacgrpTxmulticastframesGbSpec>;
#[doc = "Register `gmacgrp_txmulticastframes_gb` writer"]
pub type W = crate::W<GmacgrpTxmulticastframesGbSpec>;
#[doc = "Field `cnt` reader - Number of good and bad multicast frames transmitted"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good and bad multicast frames transmitted"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good and bad multicast frames transmitted"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good and bad multicast frames transmitted"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpTxmulticastframesGbSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good and bad multicast frames transmitted\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txmulticastframes_gb::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTxmulticastframesGbSpec;
impl crate::RegisterSpec for GmacgrpTxmulticastframesGbSpec {
    type Ux = u32;
    const OFFSET: u64 = 320u64;
}
#[doc = "`read()` method returns [`gmacgrp_txmulticastframes_gb::R`](R) reader structure"]
impl crate::Readable for GmacgrpTxmulticastframesGbSpec {}
#[doc = "`reset()` method sets gmacgrp_txmulticastframes_gb to value 0"]
impl crate::Resettable for GmacgrpTxmulticastframesGbSpec {
    const RESET_VALUE: u32 = 0;
}
