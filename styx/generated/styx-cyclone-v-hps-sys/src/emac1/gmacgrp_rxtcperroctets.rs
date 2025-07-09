// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxtcperroctets` reader"]
pub type R = crate::R<GmacgrpRxtcperroctetsSpec>;
#[doc = "Register `gmacgrp_rxtcperroctets` writer"]
pub type W = crate::W<GmacgrpRxtcperroctetsSpec>;
#[doc = "Field `rxtcp_err_octets` reader - Number of bytes received in a TCP segment with checksum errors"]
pub type RxtcpErrOctetsR = crate::FieldReader<u32>;
#[doc = "Field `rxtcp_err_octets` writer - Number of bytes received in a TCP segment with checksum errors"]
pub type RxtcpErrOctetsW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of bytes received in a TCP segment with checksum errors"]
    #[inline(always)]
    pub fn rxtcp_err_octets(&self) -> RxtcpErrOctetsR {
        RxtcpErrOctetsR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of bytes received in a TCP segment with checksum errors"]
    #[inline(always)]
    #[must_use]
    pub fn rxtcp_err_octets(&mut self) -> RxtcpErrOctetsW<GmacgrpRxtcperroctetsSpec> {
        RxtcpErrOctetsW::new(self, 0)
    }
}
#[doc = "Number of bytes received in a TCP segment with checksum errors\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxtcperroctets::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxtcperroctetsSpec;
impl crate::RegisterSpec for GmacgrpRxtcperroctetsSpec {
    type Ux = u32;
    const OFFSET: u64 = 636u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxtcperroctets::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxtcperroctetsSpec {}
#[doc = "`reset()` method sets gmacgrp_rxtcperroctets to value 0"]
impl crate::Resettable for GmacgrpRxtcperroctetsSpec {
    const RESET_VALUE: u32 = 0;
}
