// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_txmulticastframes_g` reader"]
pub type R = crate::R<GmacgrpTxmulticastframesGSpec>;
#[doc = "Register `gmacgrp_txmulticastframes_g` writer"]
pub type W = crate::W<GmacgrpTxmulticastframesGSpec>;
#[doc = "Field `cnt` reader - Number of good multicast frames transmitted"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good multicast frames transmitted"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good multicast frames transmitted"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good multicast frames transmitted"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpTxmulticastframesGSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good multicast frames transmitted\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txmulticastframes_g::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTxmulticastframesGSpec;
impl crate::RegisterSpec for GmacgrpTxmulticastframesGSpec {
    type Ux = u32;
    const OFFSET: u64 = 288u64;
}
#[doc = "`read()` method returns [`gmacgrp_txmulticastframes_g::R`](R) reader structure"]
impl crate::Readable for GmacgrpTxmulticastframesGSpec {}
#[doc = "`reset()` method sets gmacgrp_txmulticastframes_g to value 0"]
impl crate::Resettable for GmacgrpTxmulticastframesGSpec {
    const RESET_VALUE: u32 = 0;
}
