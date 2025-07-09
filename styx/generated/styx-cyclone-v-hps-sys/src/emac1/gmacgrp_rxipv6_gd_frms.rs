// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxipv6_gd_frms` reader"]
pub type R = crate::R<GmacgrpRxipv6GdFrmsSpec>;
#[doc = "Register `gmacgrp_rxipv6_gd_frms` writer"]
pub type W = crate::W<GmacgrpRxipv6GdFrmsSpec>;
#[doc = "Field `cnt` reader - Number of good IPv6 datagrams received with TCP, UDP, or ICMP payloads"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good IPv6 datagrams received with TCP, UDP, or ICMP payloads"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good IPv6 datagrams received with TCP, UDP, or ICMP payloads"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good IPv6 datagrams received with TCP, UDP, or ICMP payloads"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxipv6GdFrmsSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good IPv6 datagrams received with TCP, UDP, or ICMP payloads\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv6_gd_frms::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxipv6GdFrmsSpec;
impl crate::RegisterSpec for GmacgrpRxipv6GdFrmsSpec {
    type Ux = u32;
    const OFFSET: u64 = 548u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxipv6_gd_frms::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxipv6GdFrmsSpec {}
#[doc = "`reset()` method sets gmacgrp_rxipv6_gd_frms to value 0"]
impl crate::Resettable for GmacgrpRxipv6GdFrmsSpec {
    const RESET_VALUE: u32 = 0;
}
