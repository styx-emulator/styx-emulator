// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxudp_err_frms` reader"]
pub type R = crate::R<GmacgrpRxudpErrFrmsSpec>;
#[doc = "Register `gmacgrp_rxudp_err_frms` writer"]
pub type W = crate::W<GmacgrpRxudpErrFrmsSpec>;
#[doc = "Field `cnt` reader - Number of good IP datagrams whose UDP payload has a checksum error"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good IP datagrams whose UDP payload has a checksum error"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good IP datagrams whose UDP payload has a checksum error"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good IP datagrams whose UDP payload has a checksum error"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxudpErrFrmsSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good IP datagrams whose UDP payload has a checksum error\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxudp_err_frms::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxudpErrFrmsSpec;
impl crate::RegisterSpec for GmacgrpRxudpErrFrmsSpec {
    type Ux = u32;
    const OFFSET: u64 = 564u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxudp_err_frms::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxudpErrFrmsSpec {}
#[doc = "`reset()` method sets gmacgrp_rxudp_err_frms to value 0"]
impl crate::Resettable for GmacgrpRxudpErrFrmsSpec {
    const RESET_VALUE: u32 = 0;
}
