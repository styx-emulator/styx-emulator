// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `pinmuxgrp_MIXED2IO5` reader"]
pub type R = crate::R<PinmuxgrpMixed2io5Spec>;
#[doc = "Register `pinmuxgrp_MIXED2IO5` writer"]
pub type W = crate::W<PinmuxgrpMixed2io5Spec>;
#[doc = "Field `sel` reader - Select peripheral signals connected emac1_rx_ctl. 0 : Pin is connected to GPIO/LoanIO number 59. 1 : Pin is connected to Peripheral signal SPIM1.MOSI. 2 : Pin is connected to Peripheral signal SPIS1.MOSI. 3 : Pin is connected to Peripheral signal RGMII1.RX_CTL."]
pub type SelR = crate::FieldReader;
#[doc = "Field `sel` writer - Select peripheral signals connected emac1_rx_ctl. 0 : Pin is connected to GPIO/LoanIO number 59. 1 : Pin is connected to Peripheral signal SPIM1.MOSI. 2 : Pin is connected to Peripheral signal SPIS1.MOSI. 3 : Pin is connected to Peripheral signal RGMII1.RX_CTL."]
pub type SelW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:1 - Select peripheral signals connected emac1_rx_ctl. 0 : Pin is connected to GPIO/LoanIO number 59. 1 : Pin is connected to Peripheral signal SPIM1.MOSI. 2 : Pin is connected to Peripheral signal SPIS1.MOSI. 3 : Pin is connected to Peripheral signal RGMII1.RX_CTL."]
    #[inline(always)]
    pub fn sel(&self) -> SelR {
        SelR::new((self.bits & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Select peripheral signals connected emac1_rx_ctl. 0 : Pin is connected to GPIO/LoanIO number 59. 1 : Pin is connected to Peripheral signal SPIM1.MOSI. 2 : Pin is connected to Peripheral signal SPIS1.MOSI. 3 : Pin is connected to Peripheral signal RGMII1.RX_CTL."]
    #[inline(always)]
    #[must_use]
    pub fn sel(&mut self) -> SelW<PinmuxgrpMixed2io5Spec> {
        SelW::new(self, 0)
    }
}
#[doc = "This register is used to control the peripherals connected to emac1_rx_ctl Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed2io5::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed2io5::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PinmuxgrpMixed2io5Spec;
impl crate::RegisterSpec for PinmuxgrpMixed2io5Spec {
    type Ux = u32;
    const OFFSET: u64 = 1388u64;
}
#[doc = "`read()` method returns [`pinmuxgrp_mixed2io5::R`](R) reader structure"]
impl crate::Readable for PinmuxgrpMixed2io5Spec {}
#[doc = "`write(|w| ..)` method takes [`pinmuxgrp_mixed2io5::W`](W) writer structure"]
impl crate::Writable for PinmuxgrpMixed2io5Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets pinmuxgrp_MIXED2IO5 to value 0"]
impl crate::Resettable for PinmuxgrpMixed2io5Spec {
    const RESET_VALUE: u32 = 0;
}
