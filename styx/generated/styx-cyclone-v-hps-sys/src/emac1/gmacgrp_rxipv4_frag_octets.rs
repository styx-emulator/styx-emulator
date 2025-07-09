// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxipv4_frag_octets` reader"]
pub type R = crate::R<GmacgrpRxipv4FragOctetsSpec>;
#[doc = "Register `gmacgrp_rxipv4_frag_octets` writer"]
pub type W = crate::W<GmacgrpRxipv4FragOctetsSpec>;
#[doc = "Field `cnt` reader - Number of bytes received in fragmented IPv4 datagrams. The value in the IPv4 headers Length field is used to update this counter"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of bytes received in fragmented IPv4 datagrams. The value in the IPv4 headers Length field is used to update this counter"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of bytes received in fragmented IPv4 datagrams. The value in the IPv4 headers Length field is used to update this counter"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of bytes received in fragmented IPv4 datagrams. The value in the IPv4 headers Length field is used to update this counter"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxipv4FragOctetsSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of bytes received in fragmented IPv4 datagrams. The value in the IPv4 headers Length field is used to update this counter\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxipv4_frag_octets::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxipv4FragOctetsSpec;
impl crate::RegisterSpec for GmacgrpRxipv4FragOctetsSpec {
    type Ux = u32;
    const OFFSET: u64 = 604u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxipv4_frag_octets::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxipv4FragOctetsSpec {}
#[doc = "`reset()` method sets gmacgrp_rxipv4_frag_octets to value 0"]
impl crate::Resettable for GmacgrpRxipv4FragOctetsSpec {
    const RESET_VALUE: u32 = 0;
}
