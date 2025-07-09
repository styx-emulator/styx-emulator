// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxudp_gd_octets` reader"]
pub type R = crate::R<GmacgrpRxudpGdOctetsSpec>;
#[doc = "Register `gmacgrp_rxudp_gd_octets` writer"]
pub type W = crate::W<GmacgrpRxudpGdOctetsSpec>;
#[doc = "Field `cnt` reader - Number of bytes received in a good UDP segment. This counter does not count IP header bytes"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of bytes received in a good UDP segment. This counter does not count IP header bytes"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of bytes received in a good UDP segment. This counter does not count IP header bytes"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of bytes received in a good UDP segment. This counter does not count IP header bytes"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxudpGdOctetsSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of bytes received in a good UDP segment. This counter does not count IP header bytes\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxudp_gd_octets::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxudpGdOctetsSpec;
impl crate::RegisterSpec for GmacgrpRxudpGdOctetsSpec {
    type Ux = u32;
    const OFFSET: u64 = 624u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxudp_gd_octets::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxudpGdOctetsSpec {}
#[doc = "`reset()` method sets gmacgrp_rxudp_gd_octets to value 0"]
impl crate::Resettable for GmacgrpRxudpGdOctetsSpec {
    const RESET_VALUE: u32 = 0;
}
