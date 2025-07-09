// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `pinmuxgrp_MIXED1IO2` reader"]
pub type R = crate::R<PinmuxgrpMixed1io2Spec>;
#[doc = "Register `pinmuxgrp_MIXED1IO2` writer"]
pub type W = crate::W<PinmuxgrpMixed1io2Spec>;
#[doc = "Field `sel` reader - Select peripheral signals connected nand_cle. 0 : Pin is connected to GPIO/LoanIO number 16. 1 : Pin is connected to Peripheral signal USB1.D1. 2 : Pin is connected to Peripheral signal RGMII1.TXD1. 3 : Pin is connected to Peripheral signal NAND.cle."]
pub type SelR = crate::FieldReader;
#[doc = "Field `sel` writer - Select peripheral signals connected nand_cle. 0 : Pin is connected to GPIO/LoanIO number 16. 1 : Pin is connected to Peripheral signal USB1.D1. 2 : Pin is connected to Peripheral signal RGMII1.TXD1. 3 : Pin is connected to Peripheral signal NAND.cle."]
pub type SelW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:1 - Select peripheral signals connected nand_cle. 0 : Pin is connected to GPIO/LoanIO number 16. 1 : Pin is connected to Peripheral signal USB1.D1. 2 : Pin is connected to Peripheral signal RGMII1.TXD1. 3 : Pin is connected to Peripheral signal NAND.cle."]
    #[inline(always)]
    pub fn sel(&self) -> SelR {
        SelR::new((self.bits & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Select peripheral signals connected nand_cle. 0 : Pin is connected to GPIO/LoanIO number 16. 1 : Pin is connected to Peripheral signal USB1.D1. 2 : Pin is connected to Peripheral signal RGMII1.TXD1. 3 : Pin is connected to Peripheral signal NAND.cle."]
    #[inline(always)]
    #[must_use]
    pub fn sel(&mut self) -> SelW<PinmuxgrpMixed1io2Spec> {
        SelW::new(self, 0)
    }
}
#[doc = "This register is used to control the peripherals connected to nand_cle Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_mixed1io2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_mixed1io2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PinmuxgrpMixed1io2Spec;
impl crate::RegisterSpec for PinmuxgrpMixed1io2Spec {
    type Ux = u32;
    const OFFSET: u64 = 1288u64;
}
#[doc = "`read()` method returns [`pinmuxgrp_mixed1io2::R`](R) reader structure"]
impl crate::Readable for PinmuxgrpMixed1io2Spec {}
#[doc = "`write(|w| ..)` method takes [`pinmuxgrp_mixed1io2::W`](W) writer structure"]
impl crate::Writable for PinmuxgrpMixed1io2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets pinmuxgrp_MIXED1IO2 to value 0"]
impl crate::Resettable for PinmuxgrpMixed1io2Spec {
    const RESET_VALUE: u32 = 0;
}
