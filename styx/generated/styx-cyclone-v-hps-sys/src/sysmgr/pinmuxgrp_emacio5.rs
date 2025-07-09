// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `pinmuxgrp_EMACIO5` reader"]
pub type R = crate::R<PinmuxgrpEmacio5Spec>;
#[doc = "Register `pinmuxgrp_EMACIO5` writer"]
pub type W = crate::W<PinmuxgrpEmacio5Spec>;
#[doc = "Field `sel` reader - Select peripheral signals connected emac0_rx_d0. 0 : Pin is connected to GPIO/LoanIO number 5. 1 : Pin is connected to Peripheral signal not applicable. 2 : Pin is connected to Peripheral signal USB1.D4. 3 : Pin is connected to Peripheral signal RGMII0.RXD0."]
pub type SelR = crate::FieldReader;
#[doc = "Field `sel` writer - Select peripheral signals connected emac0_rx_d0. 0 : Pin is connected to GPIO/LoanIO number 5. 1 : Pin is connected to Peripheral signal not applicable. 2 : Pin is connected to Peripheral signal USB1.D4. 3 : Pin is connected to Peripheral signal RGMII0.RXD0."]
pub type SelW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:1 - Select peripheral signals connected emac0_rx_d0. 0 : Pin is connected to GPIO/LoanIO number 5. 1 : Pin is connected to Peripheral signal not applicable. 2 : Pin is connected to Peripheral signal USB1.D4. 3 : Pin is connected to Peripheral signal RGMII0.RXD0."]
    #[inline(always)]
    pub fn sel(&self) -> SelR {
        SelR::new((self.bits & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Select peripheral signals connected emac0_rx_d0. 0 : Pin is connected to GPIO/LoanIO number 5. 1 : Pin is connected to Peripheral signal not applicable. 2 : Pin is connected to Peripheral signal USB1.D4. 3 : Pin is connected to Peripheral signal RGMII0.RXD0."]
    #[inline(always)]
    #[must_use]
    pub fn sel(&mut self) -> SelW<PinmuxgrpEmacio5Spec> {
        SelW::new(self, 0)
    }
}
#[doc = "This register is used to control the peripherals connected to emac0_rx_d0 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio5::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio5::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PinmuxgrpEmacio5Spec;
impl crate::RegisterSpec for PinmuxgrpEmacio5Spec {
    type Ux = u32;
    const OFFSET: u64 = 1044u64;
}
#[doc = "`read()` method returns [`pinmuxgrp_emacio5::R`](R) reader structure"]
impl crate::Readable for PinmuxgrpEmacio5Spec {}
#[doc = "`write(|w| ..)` method takes [`pinmuxgrp_emacio5::W`](W) writer structure"]
impl crate::Writable for PinmuxgrpEmacio5Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets pinmuxgrp_EMACIO5 to value 0"]
impl crate::Resettable for PinmuxgrpEmacio5Spec {
    const RESET_VALUE: u32 = 0;
}
