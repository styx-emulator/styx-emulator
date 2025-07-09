// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_clr_rx_done` reader"]
pub type R = crate::R<IcClrRxDoneSpec>;
#[doc = "Register `ic_clr_rx_done` writer"]
pub type W = crate::W<IcClrRxDoneSpec>;
#[doc = "Field `clr_rx_done` reader - Read this register to clear the RX_DONE interrupt (bit 7) of the ic_raw_intr_stat register."]
pub type ClrRxDoneR = crate::BitReader;
#[doc = "Field `clr_rx_done` writer - Read this register to clear the RX_DONE interrupt (bit 7) of the ic_raw_intr_stat register."]
pub type ClrRxDoneW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Read this register to clear the RX_DONE interrupt (bit 7) of the ic_raw_intr_stat register."]
    #[inline(always)]
    pub fn clr_rx_done(&self) -> ClrRxDoneR {
        ClrRxDoneR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Read this register to clear the RX_DONE interrupt (bit 7) of the ic_raw_intr_stat register."]
    #[inline(always)]
    #[must_use]
    pub fn clr_rx_done(&mut self) -> ClrRxDoneW<IcClrRxDoneSpec> {
        ClrRxDoneW::new(self, 0)
    }
}
#[doc = "Clear RX_DONE Interrupt Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_rx_done::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcClrRxDoneSpec;
impl crate::RegisterSpec for IcClrRxDoneSpec {
    type Ux = u32;
    const OFFSET: u64 = 88u64;
}
#[doc = "`read()` method returns [`ic_clr_rx_done::R`](R) reader structure"]
impl crate::Readable for IcClrRxDoneSpec {}
#[doc = "`reset()` method sets ic_clr_rx_done to value 0"]
impl crate::Resettable for IcClrRxDoneSpec {
    const RESET_VALUE: u32 = 0;
}
