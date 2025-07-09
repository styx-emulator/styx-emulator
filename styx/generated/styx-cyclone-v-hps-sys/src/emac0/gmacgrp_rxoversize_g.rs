// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxoversize_g` reader"]
pub type R = crate::R<GmacgrpRxoversizeGSpec>;
#[doc = "Register `gmacgrp_rxoversize_g` writer"]
pub type W = crate::W<GmacgrpRxoversizeGSpec>;
#[doc = "Field `cnt` reader - Number of frames received with length greater than the maxsize (1,518 or 1,522 for VLAN tagged frames), without errors"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of frames received with length greater than the maxsize (1,518 or 1,522 for VLAN tagged frames), without errors"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of frames received with length greater than the maxsize (1,518 or 1,522 for VLAN tagged frames), without errors"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of frames received with length greater than the maxsize (1,518 or 1,522 for VLAN tagged frames), without errors"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxoversizeGSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of frames received with length greater than the maxsize (1,518 or 1,522 for VLAN tagged frames), without errors\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxoversize_g::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxoversizeGSpec;
impl crate::RegisterSpec for GmacgrpRxoversizeGSpec {
    type Ux = u32;
    const OFFSET: u64 = 424u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxoversize_g::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxoversizeGSpec {}
#[doc = "`reset()` method sets gmacgrp_rxoversize_g to value 0"]
impl crate::Resettable for GmacgrpRxoversizeGSpec {
    const RESET_VALUE: u32 = 0;
}
