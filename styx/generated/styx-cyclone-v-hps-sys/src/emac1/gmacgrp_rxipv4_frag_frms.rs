// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxipv4_frag_frms` reader"]
pub type R = crate::R<GmacgrpRxipv4FragFrmsSpec>;
#[doc = "Register `gmacgrp_rxipv4_frag_frms` writer"]
pub type W = crate::W<GmacgrpRxipv4FragFrmsSpec>;
#[doc = "Field `cnt` reader - Number of good IPv4 datagrams with fragmentation"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good IPv4 datagrams with fragmentation"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good IPv4 datagrams with fragmentation"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good IPv4 datagrams with fragmentation"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxipv4FragFrmsSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good IPv4 datagrams with fragmentation\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv4_frag_frms::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxipv4FragFrmsSpec;
impl crate::RegisterSpec for GmacgrpRxipv4FragFrmsSpec {
    type Ux = u32;
    const OFFSET: u64 = 540u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxipv4_frag_frms::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxipv4FragFrmsSpec {}
#[doc = "`reset()` method sets gmacgrp_rxipv4_frag_frms to value 0"]
impl crate::Resettable for GmacgrpRxipv4FragFrmsSpec {
    const RESET_VALUE: u32 = 0;
}
