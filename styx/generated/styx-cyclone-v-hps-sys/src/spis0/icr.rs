// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `icr` reader"]
pub type R = crate::R<IcrSpec>;
#[doc = "Register `icr` writer"]
pub type W = crate::W<IcrSpec>;
#[doc = "Field `icr` reader - This register is set if any of the interrupts below are active. A read clears the ssi_txo_intr, ssi_rxu_intr, ssi_rxo_intr, and the ssi_mst_intr interrupts. Writing to this register has no effect."]
pub type IcrR = crate::BitReader;
#[doc = "Field `icr` writer - This register is set if any of the interrupts below are active. A read clears the ssi_txo_intr, ssi_rxu_intr, ssi_rxo_intr, and the ssi_mst_intr interrupts. Writing to this register has no effect."]
pub type IcrW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - This register is set if any of the interrupts below are active. A read clears the ssi_txo_intr, ssi_rxu_intr, ssi_rxo_intr, and the ssi_mst_intr interrupts. Writing to this register has no effect."]
    #[inline(always)]
    pub fn icr(&self) -> IcrR {
        IcrR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This register is set if any of the interrupts below are active. A read clears the ssi_txo_intr, ssi_rxu_intr, ssi_rxo_intr, and the ssi_mst_intr interrupts. Writing to this register has no effect."]
    #[inline(always)]
    #[must_use]
    pub fn icr(&mut self) -> IcrW<IcrSpec> {
        IcrW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`icr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcrSpec;
impl crate::RegisterSpec for IcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 72u64;
}
#[doc = "`read()` method returns [`icr::R`](R) reader structure"]
impl crate::Readable for IcrSpec {}
#[doc = "`reset()` method sets icr to value 0"]
impl crate::Resettable for IcrSpec {
    const RESET_VALUE: u32 = 0;
}
