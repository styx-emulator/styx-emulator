// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxipv4_udsbl_frms` reader"]
pub type R = crate::R<GmacgrpRxipv4UdsblFrmsSpec>;
#[doc = "Register `gmacgrp_rxipv4_udsbl_frms` writer"]
pub type W = crate::W<GmacgrpRxipv4UdsblFrmsSpec>;
#[doc = "Field `cnt` reader - Number of good IPv4 datagrams received that had a UDP payload with checksum disabled"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good IPv4 datagrams received that had a UDP payload with checksum disabled"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good IPv4 datagrams received that had a UDP payload with checksum disabled"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good IPv4 datagrams received that had a UDP payload with checksum disabled"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxipv4UdsblFrmsSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good IPv4 datagrams received that had a UDP payload with checksum disabled\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv4_udsbl_frms::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxipv4UdsblFrmsSpec;
impl crate::RegisterSpec for GmacgrpRxipv4UdsblFrmsSpec {
    type Ux = u32;
    const OFFSET: u64 = 544u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxipv4_udsbl_frms::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxipv4UdsblFrmsSpec {}
#[doc = "`reset()` method sets gmacgrp_rxipv4_udsbl_frms to value 0"]
impl crate::Resettable for GmacgrpRxipv4UdsblFrmsSpec {
    const RESET_VALUE: u32 = 0;
}
