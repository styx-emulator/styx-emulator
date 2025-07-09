// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxfifooverflow` reader"]
pub type R = crate::R<GmacgrpRxfifooverflowSpec>;
#[doc = "Register `gmacgrp_rxfifooverflow` writer"]
pub type W = crate::W<GmacgrpRxfifooverflowSpec>;
#[doc = "Field `cnt` reader - Number of missed received frames due to FIFO overflow"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of missed received frames due to FIFO overflow"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of missed received frames due to FIFO overflow"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of missed received frames due to FIFO overflow"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxfifooverflowSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of missed received frames due to FIFO overflow\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxfifooverflow::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxfifooverflowSpec;
impl crate::RegisterSpec for GmacgrpRxfifooverflowSpec {
    type Ux = u32;
    const OFFSET: u64 = 468u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxfifooverflow::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxfifooverflowSpec {}
#[doc = "`reset()` method sets gmacgrp_rxfifooverflow to value 0"]
impl crate::Resettable for GmacgrpRxfifooverflowSpec {
    const RESET_VALUE: u32 = 0;
}
