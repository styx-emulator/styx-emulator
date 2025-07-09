// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxipv4_hdrerr_octets` reader"]
pub type R = crate::R<GmacgrpRxipv4HdrerrOctetsSpec>;
#[doc = "Register `gmacgrp_rxipv4_hdrerr_octets` writer"]
pub type W = crate::W<GmacgrpRxipv4HdrerrOctetsSpec>;
#[doc = "Field `cnt` reader - Number of bytes received in IPv4 datagrams with header errors (checksum, length, version mismatch). The value in the Length field of IPv4 header is used to update this counter"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of bytes received in IPv4 datagrams with header errors (checksum, length, version mismatch). The value in the Length field of IPv4 header is used to update this counter"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of bytes received in IPv4 datagrams with header errors (checksum, length, version mismatch). The value in the Length field of IPv4 header is used to update this counter"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of bytes received in IPv4 datagrams with header errors (checksum, length, version mismatch). The value in the Length field of IPv4 header is used to update this counter"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxipv4HdrerrOctetsSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of bytes received in IPv4 datagrams with header errors (checksum, length, version mismatch). The value in the Length field of IPv4 header is used to update this counter\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv4_hdrerr_octets::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxipv4HdrerrOctetsSpec;
impl crate::RegisterSpec for GmacgrpRxipv4HdrerrOctetsSpec {
    type Ux = u32;
    const OFFSET: u64 = 596u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxipv4_hdrerr_octets::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxipv4HdrerrOctetsSpec {}
#[doc = "`reset()` method sets gmacgrp_rxipv4_hdrerr_octets to value 0"]
impl crate::Resettable for GmacgrpRxipv4HdrerrOctetsSpec {
    const RESET_VALUE: u32 = 0;
}
