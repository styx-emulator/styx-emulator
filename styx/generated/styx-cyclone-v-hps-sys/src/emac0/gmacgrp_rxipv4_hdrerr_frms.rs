// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxipv4_hdrerr_frms` reader"]
pub type R = crate::R<GmacgrpRxipv4HdrerrFrmsSpec>;
#[doc = "Register `gmacgrp_rxipv4_hdrerr_frms` writer"]
pub type W = crate::W<GmacgrpRxipv4HdrerrFrmsSpec>;
#[doc = "Field `cnt` reader - Number of IPv4 datagrams received with header (checksum, length, or version mismatch) errors"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of IPv4 datagrams received with header (checksum, length, or version mismatch) errors"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of IPv4 datagrams received with header (checksum, length, or version mismatch) errors"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of IPv4 datagrams received with header (checksum, length, or version mismatch) errors"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxipv4HdrerrFrmsSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of IPv4 datagrams received with header (checksum, length, or version mismatch) errors\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv4_hdrerr_frms::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxipv4HdrerrFrmsSpec;
impl crate::RegisterSpec for GmacgrpRxipv4HdrerrFrmsSpec {
    type Ux = u32;
    const OFFSET: u64 = 532u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxipv4_hdrerr_frms::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxipv4HdrerrFrmsSpec {}
#[doc = "`reset()` method sets gmacgrp_rxipv4_hdrerr_frms to value 0"]
impl crate::Resettable for GmacgrpRxipv4HdrerrFrmsSpec {
    const RESET_VALUE: u32 = 0;
}
