// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxudp_gd_frms` reader"]
pub type R = crate::R<GmacgrpRxudpGdFrmsSpec>;
#[doc = "Register `gmacgrp_rxudp_gd_frms` writer"]
pub type W = crate::W<GmacgrpRxudpGdFrmsSpec>;
#[doc = "Field `cnt` reader - Number of good IP datagrams with a good UDP payload. This counter is not updated when the counter is incremented"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good IP datagrams with a good UDP payload. This counter is not updated when the counter is incremented"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good IP datagrams with a good UDP payload. This counter is not updated when the counter is incremented"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good IP datagrams with a good UDP payload. This counter is not updated when the counter is incremented"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxudpGdFrmsSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good IP datagrams with a good UDP payload. This counter is not updated when the counter is incremented\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxudp_gd_frms::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxudpGdFrmsSpec;
impl crate::RegisterSpec for GmacgrpRxudpGdFrmsSpec {
    type Ux = u32;
    const OFFSET: u64 = 560u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxudp_gd_frms::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxudpGdFrmsSpec {}
#[doc = "`reset()` method sets gmacgrp_rxudp_gd_frms to value 0"]
impl crate::Resettable for GmacgrpRxudpGdFrmsSpec {
    const RESET_VALUE: u32 = 0;
}
