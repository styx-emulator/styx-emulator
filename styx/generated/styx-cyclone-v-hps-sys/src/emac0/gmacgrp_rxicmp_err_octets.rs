// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxicmp_err_octets` reader"]
pub type R = crate::R<GmacgrpRxicmpErrOctetsSpec>;
#[doc = "Register `gmacgrp_rxicmp_err_octets` writer"]
pub type W = crate::W<GmacgrpRxicmpErrOctetsSpec>;
#[doc = "Field `cnt` reader - Number of bytes received in an ICMP segment with checksum errors"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of bytes received in an ICMP segment with checksum errors"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of bytes received in an ICMP segment with checksum errors"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of bytes received in an ICMP segment with checksum errors"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxicmpErrOctetsSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of bytes received in an ICMP segment with checksum errors\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxicmp_err_octets::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxicmpErrOctetsSpec;
impl crate::RegisterSpec for GmacgrpRxicmpErrOctetsSpec {
    type Ux = u32;
    const OFFSET: u64 = 644u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxicmp_err_octets::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxicmpErrOctetsSpec {}
#[doc = "`reset()` method sets gmacgrp_rxicmp_err_octets to value 0"]
impl crate::Resettable for GmacgrpRxicmpErrOctetsSpec {
    const RESET_VALUE: u32 = 0;
}
