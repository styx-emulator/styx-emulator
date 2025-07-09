// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxipv4_udsbl_octets` reader"]
pub type R = crate::R<GmacgrpRxipv4UdsblOctetsSpec>;
#[doc = "Register `gmacgrp_rxipv4_udsbl_octets` writer"]
pub type W = crate::W<GmacgrpRxipv4UdsblOctetsSpec>;
#[doc = "Field `cnt` reader - Number of bytes received in a UDP segment that had the UDP checksum disabled. This counter does not count IP Header bytes"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of bytes received in a UDP segment that had the UDP checksum disabled. This counter does not count IP Header bytes"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of bytes received in a UDP segment that had the UDP checksum disabled. This counter does not count IP Header bytes"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of bytes received in a UDP segment that had the UDP checksum disabled. This counter does not count IP Header bytes"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxipv4UdsblOctetsSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of bytes received in a UDP segment that had the UDP checksum disabled. This counter does not count IP Header bytes\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv4_udsbl_octets::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxipv4UdsblOctetsSpec;
impl crate::RegisterSpec for GmacgrpRxipv4UdsblOctetsSpec {
    type Ux = u32;
    const OFFSET: u64 = 608u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxipv4_udsbl_octets::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxipv4UdsblOctetsSpec {}
#[doc = "`reset()` method sets gmacgrp_rxipv4_udsbl_octets to value 0"]
impl crate::Resettable for GmacgrpRxipv4UdsblOctetsSpec {
    const RESET_VALUE: u32 = 0;
}
