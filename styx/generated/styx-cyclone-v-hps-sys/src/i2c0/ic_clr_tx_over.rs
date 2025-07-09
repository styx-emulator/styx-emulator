// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_clr_tx_over` reader"]
pub type R = crate::R<IcClrTxOverSpec>;
#[doc = "Register `ic_clr_tx_over` writer"]
pub type W = crate::W<IcClrTxOverSpec>;
#[doc = "Field `clr_tx_over` reader - Read this register to clear the TX_OVER interrupt (bit 3) of the ic_raw_intr_stat register."]
pub type ClrTxOverR = crate::BitReader;
#[doc = "Field `clr_tx_over` writer - Read this register to clear the TX_OVER interrupt (bit 3) of the ic_raw_intr_stat register."]
pub type ClrTxOverW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Read this register to clear the TX_OVER interrupt (bit 3) of the ic_raw_intr_stat register."]
    #[inline(always)]
    pub fn clr_tx_over(&self) -> ClrTxOverR {
        ClrTxOverR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Read this register to clear the TX_OVER interrupt (bit 3) of the ic_raw_intr_stat register."]
    #[inline(always)]
    #[must_use]
    pub fn clr_tx_over(&mut self) -> ClrTxOverW<IcClrTxOverSpec> {
        ClrTxOverW::new(self, 0)
    }
}
#[doc = "Clears Over Interrupts\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_tx_over::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcClrTxOverSpec;
impl crate::RegisterSpec for IcClrTxOverSpec {
    type Ux = u32;
    const OFFSET: u64 = 76u64;
}
#[doc = "`read()` method returns [`ic_clr_tx_over::R`](R) reader structure"]
impl crate::Readable for IcClrTxOverSpec {}
#[doc = "`reset()` method sets ic_clr_tx_over to value 0"]
impl crate::Resettable for IcClrTxOverSpec {
    const RESET_VALUE: u32 = 0;
}
