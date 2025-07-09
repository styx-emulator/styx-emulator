// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_txmulticol_g` reader"]
pub type R = crate::R<GmacgrpTxmulticolGSpec>;
#[doc = "Register `gmacgrp_txmulticol_g` writer"]
pub type W = crate::W<GmacgrpTxmulticolGSpec>;
#[doc = "Field `cnt` reader - Number of successfully transmitted frames after more than a single collision in Half-duplex mode"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of successfully transmitted frames after more than a single collision in Half-duplex mode"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of successfully transmitted frames after more than a single collision in Half-duplex mode"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of successfully transmitted frames after more than a single collision in Half-duplex mode"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpTxmulticolGSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of successfully transmitted frames after more than a single collision in Half-duplex mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txmulticol_g::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTxmulticolGSpec;
impl crate::RegisterSpec for GmacgrpTxmulticolGSpec {
    type Ux = u32;
    const OFFSET: u64 = 336u64;
}
#[doc = "`read()` method returns [`gmacgrp_txmulticol_g::R`](R) reader structure"]
impl crate::Readable for GmacgrpTxmulticolGSpec {}
#[doc = "`reset()` method sets gmacgrp_txmulticol_g to value 0"]
impl crate::Resettable for GmacgrpTxmulticolGSpec {
    const RESET_VALUE: u32 = 0;
}
