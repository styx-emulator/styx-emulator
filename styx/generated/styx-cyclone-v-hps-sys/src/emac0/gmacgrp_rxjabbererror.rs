// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `gmacgrp_rxjabbererror` reader"]
pub type R = crate::R<GmacgrpRxjabbererrorSpec>;
#[doc = "Register `gmacgrp_rxjabbererror` writer"]
pub type W = crate::W<GmacgrpRxjabbererrorSpec>;
#[doc = "Field `cnt` reader - Number of giant frames received with length (including CRC) greater than 1,518 bytes (1,522 bytes for VLAN tagged) and with CRC error. If Jumbo Frame mode is enabled, then frames of length greater than 9,018 bytes (9,022 for VLAN tagged) are considered as giant frames"]
pub type CntR = crate::FieldReader<u32>;
#[doc = "Field `cnt` writer - Number of giant frames received with length (including CRC) greater than 1,518 bytes (1,522 bytes for VLAN tagged) and with CRC error. If Jumbo Frame mode is enabled, then frames of length greater than 9,018 bytes (9,022 for VLAN tagged) are considered as giant frames"]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Number of giant frames received with length (including CRC) greater than 1,518 bytes (1,522 bytes for VLAN tagged) and with CRC error. If Jumbo Frame mode is enabled, then frames of length greater than 9,018 bytes (9,022 for VLAN tagged) are considered as giant frames"]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Number of giant frames received with length (including CRC) greater than 1,518 bytes (1,522 bytes for VLAN tagged) and with CRC error. If Jumbo Frame mode is enabled, then frames of length greater than 9,018 bytes (9,022 for VLAN tagged) are considered as giant frames"]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<GmacgrpRxjabbererrorSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Number of giant frames received with length (including CRC) greater than 1,518 bytes (1,522 bytes for VLAN tagged) and with CRC error. If Jumbo Frame mode is enabled, then frames of length greater than 9,018 bytes (9,022 for VLAN tagged) are considered as giant frames\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`gmacgrp_rxjabbererror::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GmacgrpRxjabbererrorSpec;
impl crate::RegisterSpec for GmacgrpRxjabbererrorSpec {
    type Ux = u32;
    const OFFSET: u64 = 416u64;
}
#[doc = "`read()` method returns [`gmacgrp_rxjabbererror::R`](R) reader structure"]
impl crate::Readable for GmacgrpRxjabbererrorSpec {}
#[doc = "`reset()` method sets gmacgrp_rxjabbererror to value 0"]
impl crate::Resettable for GmacgrpRxjabbererrorSpec {
    const RESET_VALUE: u32 = 0;
}
