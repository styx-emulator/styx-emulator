// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxipv6_nopay_octets` reader"]
pub type R = crate::R<GmacgrpRxipv6NopayOctetsSpec>;
#[doc = "Register `gmacgrp_rxipv6_nopay_octets` writer"]
pub type W = crate::W<GmacgrpRxipv6NopayOctetsSpec>;
#[doc = "Field `cnt` reader - Number of bytes received in IPv6 datagrams that did not have a TCP, UDP, or ICMP payload. The value in the IPv6 headers Length field is used to update this counter"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of bytes received in IPv6 datagrams that did not have a TCP, UDP, or ICMP payload. The value in the IPv6 headers Length field is used to update this counter"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of bytes received in IPv6 datagrams that did not have a TCP, UDP, or ICMP payload. The value in the IPv6 headers Length field is used to update this counter"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of bytes received in IPv6 datagrams that did not have a TCP, UDP, or ICMP payload. The value in the IPv6 headers Length field is used to update this counter"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxipv6NopayOctetsSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of bytes received in IPv6 datagrams that did not have a TCP, UDP, or ICMP payload. The value in the IPv6 headers Length field is used to update this counter\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv6_nopay_octets::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxipv6NopayOctetsSpec;
impl crate::RegisterSpec for GmacgrpRxipv6NopayOctetsSpec {
    type Ux = u32;
    const OFFSET: u64 = 620u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxipv6_nopay_octets::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxipv6NopayOctetsSpec {}
#[doc = "`reset()` method sets gmacgrp_rxipv6_nopay_octets to value 0"]
impl crate::Resettable for GmacgrpRxipv6NopayOctetsSpec {
    const RESET_VALUE: u32 = 0;
}
