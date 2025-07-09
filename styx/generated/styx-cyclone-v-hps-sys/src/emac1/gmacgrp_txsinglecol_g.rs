// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_txsinglecol_g` reader"]
pub type R = crate::R<GmacgrpTxsinglecolGSpec>;
#[doc = "Register `gmacgrp_txsinglecol_g` writer"]
pub type W = crate::W<GmacgrpTxsinglecolGSpec>;
#[doc = "Field `cnt` reader - Number of successfully transmitted frames after a single collision in Half-duplex mode"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of successfully transmitted frames after a single collision in Half-duplex mode"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of successfully transmitted frames after a single collision in Half-duplex mode"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of successfully transmitted frames after a single collision in Half-duplex mode"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpTxsinglecolGSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of successfully transmitted frames after a single collision in Half-duplex mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_txsinglecol_g::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpTxsinglecolGSpec;
impl crate::RegisterSpec for GmacgrpTxsinglecolGSpec {
    type Ux = u32;
    const OFFSET: u64 = 332u64;
}
#[doc = "`read()` method returns [`gmacgrp_txsinglecol_g::R`](R) reader structure"]
impl crate::Readable for GmacgrpTxsinglecolGSpec {}
#[doc = "`reset()` method sets gmacgrp_txsinglecol_g to value 0"]
impl crate::Resettable for GmacgrpTxsinglecolGSpec {
    const RESET_VALUE: u32 = 0;
}
