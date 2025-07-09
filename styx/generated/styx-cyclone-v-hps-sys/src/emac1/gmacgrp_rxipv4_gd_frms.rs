// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxipv4_gd_frms` reader"]
pub type R = crate::R<GmacgrpRxipv4GdFrmsSpec>;
#[doc = "Register `gmacgrp_rxipv4_gd_frms` writer"]
pub type W = crate::W<GmacgrpRxipv4GdFrmsSpec>;
#[doc = "Field `cnt` reader - Number of good IPv4 datagrams received with the TCP, UDP, or ICMP payload"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good IPv4 datagrams received with the TCP, UDP, or ICMP payload"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good IPv4 datagrams received with the TCP, UDP, or ICMP payload"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good IPv4 datagrams received with the TCP, UDP, or ICMP payload"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxipv4GdFrmsSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good IPv4 datagrams received with the TCP, UDP, or ICMP payload\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv4_gd_frms::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxipv4GdFrmsSpec;
impl crate::RegisterSpec for GmacgrpRxipv4GdFrmsSpec {
    type Ux = u32;
    const OFFSET: u64 = 528u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxipv4_gd_frms::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxipv4GdFrmsSpec {}
#[doc = "`reset()` method sets gmacgrp_rxipv4_gd_frms to value 0"]
impl crate::Resettable for GmacgrpRxipv4GdFrmsSpec {
    const RESET_VALUE: u32 = 0;
}
