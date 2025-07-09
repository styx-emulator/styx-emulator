// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `txoicr` reader"]
pub type R = crate::R<TxoicrSpec>;
#[doc = "Register `txoicr` writer"]
pub type W = crate::W<TxoicrSpec>;
#[doc = "Field `txoicr` reader - This register reflects the status of the interrupt. A read from this register clears the ssi_txo_intr interrupt; writing has no effect."]
pub type TxoicrR = crate::BitReader;
#[doc = "Field `txoicr` writer - This register reflects the status of the interrupt. A read from this register clears the ssi_txo_intr interrupt; writing has no effect."]
pub type TxoicrW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - This register reflects the status of the interrupt. A read from this register clears the ssi_txo_intr interrupt; writing has no effect."]
    #[inline(always)]
    pub fn txoicr(&self) -> TxoicrR {
        TxoicrR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This register reflects the status of the interrupt. A read from this register clears the ssi_txo_intr interrupt; writing has no effect."]
    #[inline(always)]
    #[must_use]
    pub fn txoicr(&mut self) -> TxoicrW<TxoicrSpec> {
        TxoicrW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`txoicr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TxoicrSpec;
impl crate::RegisterSpec for TxoicrSpec {
    type Ux = u32;
    const OFFSET: u64 = 56u64;
}
#[doc = "`read()` method returns [`txoicr::R`](R) reader structure"]
impl crate::Readable for TxoicrSpec {}
#[doc = "`reset()` method sets txoicr to value 0"]
impl crate::Resettable for TxoicrSpec {
    const RESET_VALUE: u32 = 0;
}
