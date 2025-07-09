// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `pinmuxgrp_EMACIO6` reader"]
pub type R = crate::R<PinmuxgrpEmacio6Spec>;
#[doc = "Register `pinmuxgrp_EMACIO6` writer"]
pub type W = crate::W<PinmuxgrpEmacio6Spec>;
#[doc = "Field `sel` reader - Select peripheral signals connected emac0_mdio. 0 : Pin is connected to GPIO/LoanIO number 6. 1 : Pin is connected to Peripheral signal I2C2.SDA. 2 : Pin is connected to Peripheral signal USB1.D5. 3 : Pin is connected to Peripheral signal RGMII0.MDIO."]
pub type SelR = crate::FieldReader;
#[doc = "Field `sel` writer - Select peripheral signals connected emac0_mdio. 0 : Pin is connected to GPIO/LoanIO number 6. 1 : Pin is connected to Peripheral signal I2C2.SDA. 2 : Pin is connected to Peripheral signal USB1.D5. 3 : Pin is connected to Peripheral signal RGMII0.MDIO."]
pub type SelW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:1 - Select peripheral signals connected emac0_mdio. 0 : Pin is connected to GPIO/LoanIO number 6. 1 : Pin is connected to Peripheral signal I2C2.SDA. 2 : Pin is connected to Peripheral signal USB1.D5. 3 : Pin is connected to Peripheral signal RGMII0.MDIO."]
    #[inline(always)]
    pub fn sel(&self) -> SelR {
        SelR::new((self.bits & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Select peripheral signals connected emac0_mdio. 0 : Pin is connected to GPIO/LoanIO number 6. 1 : Pin is connected to Peripheral signal I2C2.SDA. 2 : Pin is connected to Peripheral signal USB1.D5. 3 : Pin is connected to Peripheral signal RGMII0.MDIO."]
    #[inline(always)]
    #[must_use]
    pub fn sel(&mut self) -> SelW<PinmuxgrpEmacio6Spec> {
        SelW::new(self, 0)
    }
}
#[doc = "This register is used to control the peripherals connected to emac0_mdio Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_emacio6::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_emacio6::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PinmuxgrpEmacio6Spec;
impl crate::RegisterSpec for PinmuxgrpEmacio6Spec {
    type Ux = u32;
    const OFFSET: u64 = 1048u64;
}
#[doc = "`read()` method returns [`pinmuxgrp_emacio6::R`](R) reader structure"]
impl crate::Readable for PinmuxgrpEmacio6Spec {}
#[doc = "`write(|w| ..)` method takes [`pinmuxgrp_emacio6::W`](W) writer structure"]
impl crate::Writable for PinmuxgrpEmacio6Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets pinmuxgrp_EMACIO6 to value 0"]
impl crate::Resettable for PinmuxgrpEmacio6Spec {
    const RESET_VALUE: u32 = 0;
}
