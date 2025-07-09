// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxipv6_hdrerr_frms` reader"]
pub type R = crate::R<GmacgrpRxipv6HdrerrFrmsSpec>;
#[doc = "Register `gmacgrp_rxipv6_hdrerr_frms` writer"]
pub type W = crate::W<GmacgrpRxipv6HdrerrFrmsSpec>;
#[doc = "Field `cnt` reader - Number of IPv6 datagrams received with header errors (length or version mismatch)"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of IPv6 datagrams received with header errors (length or version mismatch)"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of IPv6 datagrams received with header errors (length or version mismatch)"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of IPv6 datagrams received with header errors (length or version mismatch)"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxipv6HdrerrFrmsSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of IPv6 datagrams received with header errors (length or version mismatch)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv6_hdrerr_frms::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxipv6HdrerrFrmsSpec;
impl crate::RegisterSpec for GmacgrpRxipv6HdrerrFrmsSpec {
    type Ux = u32;
    const OFFSET: u64 = 552u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxipv6_hdrerr_frms::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxipv6HdrerrFrmsSpec {}
#[doc = "`reset()` method sets gmacgrp_rxipv6_hdrerr_frms to value 0"]
impl crate::Resettable for GmacgrpRxipv6HdrerrFrmsSpec {
    const RESET_VALUE: u32 = 0;
}
