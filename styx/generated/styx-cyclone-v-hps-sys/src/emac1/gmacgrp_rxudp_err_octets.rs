// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxudp_err_octets` reader"]
pub type R = crate::R<GmacgrpRxudpErrOctetsSpec>;
#[doc = "Register `gmacgrp_rxudp_err_octets` writer"]
pub type W = crate::W<GmacgrpRxudpErrOctetsSpec>;
#[doc = "Field `cnt` reader - Number of bytes received in a UDP segment that had checksum errors"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of bytes received in a UDP segment that had checksum errors"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of bytes received in a UDP segment that had checksum errors"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of bytes received in a UDP segment that had checksum errors"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxudpErrOctetsSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of bytes received in a UDP segment that had checksum errors\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxudp_err_octets::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxudpErrOctetsSpec;
impl crate::RegisterSpec for GmacgrpRxudpErrOctetsSpec {
    type Ux = u32;
    const OFFSET: u64 = 628u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxudp_err_octets::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxudpErrOctetsSpec {}
#[doc = "`reset()` method sets gmacgrp_rxudp_err_octets to value 0"]
impl crate::Resettable for GmacgrpRxudpErrOctetsSpec {
    const RESET_VALUE: u32 = 0;
}
