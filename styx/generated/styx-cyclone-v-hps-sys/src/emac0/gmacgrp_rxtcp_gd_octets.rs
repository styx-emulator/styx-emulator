// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxtcp_gd_octets` reader"]
pub type R = crate::R<GmacgrpRxtcpGdOctetsSpec>;
#[doc = "Register `gmacgrp_rxtcp_gd_octets` writer"]
pub type W = crate::W<GmacgrpRxtcpGdOctetsSpec>;
#[doc = "Field `cnt` reader - Number of bytes received in a good TCP segment"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of bytes received in a good TCP segment"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of bytes received in a good TCP segment"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of bytes received in a good TCP segment"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxtcpGdOctetsSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of bytes received in a good TCP segment\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxtcp_gd_octets::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxtcpGdOctetsSpec;
impl crate::RegisterSpec for GmacgrpRxtcpGdOctetsSpec {
    type Ux = u32;
    const OFFSET: u64 = 632u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxtcp_gd_octets::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxtcpGdOctetsSpec {}
#[doc = "`reset()` method sets gmacgrp_rxtcp_gd_octets to value 0"]
impl crate::Resettable for GmacgrpRxtcpGdOctetsSpec {
    const RESET_VALUE: u32 = 0;
}
