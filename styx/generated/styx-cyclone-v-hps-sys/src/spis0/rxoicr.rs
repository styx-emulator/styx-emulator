// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `rxoicr` reader"]
pub type R = crate::R<RxoicrSpec>;
#[doc = "Register `rxoicr` writer"]
pub type W = crate::W<RxoicrSpec>;
#[doc = "Field `rxoicr` reader - This register reflects the status of the interrupt. A read from this register clears the ssi_rxo_intr interrupt; writing has no effect."]
pub type RxoicrR = crate::BitReader;
#[doc = "Field `rxoicr` writer - This register reflects the status of the interrupt. A read from this register clears the ssi_rxo_intr interrupt; writing has no effect."]
pub type RxoicrW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - This register reflects the status of the interrupt. A read from this register clears the ssi_rxo_intr interrupt; writing has no effect."]
    #[inline(always)]
    pub fn rxoicr(&self) -> RxoicrR {
        RxoicrR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This register reflects the status of the interrupt. A read from this register clears the ssi_rxo_intr interrupt; writing has no effect."]
    #[inline(always)]
    #[must_use]
    pub fn rxoicr(&mut self) -> RxoicrW<RxoicrSpec> {
        RxoicrW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`rxoicr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RxoicrSpec;
impl crate::RegisterSpec for RxoicrSpec {
    type Ux = u32;
    const OFFSET: u64 = 60u64;
}
#[doc = "`read()` method returns [`rxoicr::R`](R) reader structure"]
impl crate::Readable for RxoicrSpec {}
#[doc = "`reset()` method sets rxoicr to value 0"]
impl crate::Resettable for RxoicrSpec {
    const RESET_VALUE: u32 = 0;
}
