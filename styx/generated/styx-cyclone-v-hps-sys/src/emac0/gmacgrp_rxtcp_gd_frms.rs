// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxtcp_gd_frms` reader"]
pub type R = crate::R<GmacgrpRxtcpGdFrmsSpec>;
#[doc = "Register `gmacgrp_rxtcp_gd_frms` writer"]
pub type W = crate::W<GmacgrpRxtcpGdFrmsSpec>;
#[doc = "Field `cnt` reader - Number of good IP datagrams with a good TCP payload"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of good IP datagrams with a good TCP payload"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of good IP datagrams with a good TCP payload"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of good IP datagrams with a good TCP payload"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxtcpGdFrmsSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of good IP datagrams with a good TCP payload\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxtcp_gd_frms::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxtcpGdFrmsSpec;
impl crate::RegisterSpec for GmacgrpRxtcpGdFrmsSpec {
    type Ux = u32;
    const OFFSET: u64 = 568u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxtcp_gd_frms::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxtcpGdFrmsSpec {}
#[doc = "`reset()` method sets gmacgrp_rxtcp_gd_frms to value 0"]
impl crate::Resettable for GmacgrpRxtcpGdFrmsSpec {
    const RESET_VALUE: u32 = 0;
}
