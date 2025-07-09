// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_clr_rx_over` reader"]
pub type R = crate::R<IcClrRxOverSpec>;
#[doc = "Register `ic_clr_rx_over` writer"]
pub type W = crate::W<IcClrRxOverSpec>;
#[doc = "Field `clr_rx_over` reader - Read this register to clear the RX_OVER interrupt bit 1 of the ic_raw_intr_stat register."]
pub type ClrRxOverR = crate::BitReader;
#[doc = "Field `clr_rx_over` writer - Read this register to clear the RX_OVER interrupt bit 1 of the ic_raw_intr_stat register."]
pub type ClrRxOverW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Read this register to clear the RX_OVER interrupt bit 1 of the ic_raw_intr_stat register."]
    #[inline(always)]
    pub fn clr_rx_over(&self) -> ClrRxOverR {
        ClrRxOverR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Read this register to clear the RX_OVER interrupt bit 1 of the ic_raw_intr_stat register."]
    #[inline(always)]
    #[must_use]
    pub fn clr_rx_over(&mut self) -> ClrRxOverW<IcClrRxOverSpec> {
        ClrRxOverW::new(self, 0)
    }
}
#[doc = "Clears Rx over Interrupt Bit\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_rx_over::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcClrRxOverSpec;
impl crate::RegisterSpec for IcClrRxOverSpec {
    type Ux = u32;
    const OFFSET: u64 = 72u64;
}
#[doc = "`read()` method returns [`ic_clr_rx_over::R`](R) reader structure"]
impl crate::Readable for IcClrRxOverSpec {}
#[doc = "`reset()` method sets ic_clr_rx_over to value 0"]
impl crate::Resettable for IcClrRxOverSpec {
    const RESET_VALUE: u32 = 0;
}
