// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxipv6_gd_octets` reader"]
pub type R = crate::R<GmacgrpRxipv6GdOctetsSpec>;
#[doc = "Register `gmacgrp_rxipv6_gd_octets` writer"]
pub type W = crate::W<GmacgrpRxipv6GdOctetsSpec>;
#[doc = "Field `cnt` reader - Number of bytes received in good IPv6 datagrams encapsulating TCP, UDP or ICMPv6 data"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of bytes received in good IPv6 datagrams encapsulating TCP, UDP or ICMPv6 data"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of bytes received in good IPv6 datagrams encapsulating TCP, UDP or ICMPv6 data"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of bytes received in good IPv6 datagrams encapsulating TCP, UDP or ICMPv6 data"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxipv6GdOctetsSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of bytes received in good IPv6 datagrams encapsulating TCP, UDP or ICMPv6 data\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv6_gd_octets::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxipv6GdOctetsSpec;
impl crate::RegisterSpec for GmacgrpRxipv6GdOctetsSpec {
    type Ux = u32;
    const OFFSET: u64 = 612u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxipv6_gd_octets::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxipv6GdOctetsSpec {}
#[doc = "`reset()` method sets gmacgrp_rxipv6_gd_octets to value 0"]
impl crate::Resettable for GmacgrpRxipv6GdOctetsSpec {
    const RESET_VALUE: u32 = 0;
}
