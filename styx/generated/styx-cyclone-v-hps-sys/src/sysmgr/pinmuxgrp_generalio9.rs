// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `pinmuxgrp_GENERALIO9` reader"]
pub type R = crate::R<PinmuxgrpGeneralio9Spec>;
#[doc = "Register `pinmuxgrp_GENERALIO9` writer"]
pub type W = crate::W<PinmuxgrpGeneralio9Spec>;
#[doc = "Field `sel` reader - Select peripheral signals connected spim0_clk. 0 : Pin is connected to GPIO/LoanIO number 57. 1 : Pin is connected to Peripheral signal UART0.CTS. 2 : Pin is connected to Peripheral signal I2C1.SDA. 3 : Pin is connected to Peripheral signal SPIM0.CLK."]
pub type SelR = crate::FieldReader;
#[doc = "Field `sel` writer - Select peripheral signals connected spim0_clk. 0 : Pin is connected to GPIO/LoanIO number 57. 1 : Pin is connected to Peripheral signal UART0.CTS. 2 : Pin is connected to Peripheral signal I2C1.SDA. 3 : Pin is connected to Peripheral signal SPIM0.CLK."]
pub type SelW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:1 - Select peripheral signals connected spim0_clk. 0 : Pin is connected to GPIO/LoanIO number 57. 1 : Pin is connected to Peripheral signal UART0.CTS. 2 : Pin is connected to Peripheral signal I2C1.SDA. 3 : Pin is connected to Peripheral signal SPIM0.CLK."]
    #[inline(always)]
    pub fn sel(&self) -> SelR {
        SelR::new((self.bits & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Select peripheral signals connected spim0_clk. 0 : Pin is connected to GPIO/LoanIO number 57. 1 : Pin is connected to Peripheral signal UART0.CTS. 2 : Pin is connected to Peripheral signal I2C1.SDA. 3 : Pin is connected to Peripheral signal SPIM0.CLK."]
    #[inline(always)]
    #[must_use]
    pub fn sel(&mut self) -> SelW<PinmuxgrpGeneralio9Spec> {
        SelW::new(self, 0)
    }
}
#[doc = "This register is used to control the peripherals connected to spim0_clk Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio9::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio9::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PinmuxgrpGeneralio9Spec;
impl crate::RegisterSpec for PinmuxgrpGeneralio9Spec {
    type Ux = u32;
    const OFFSET: u64 = 1188u64;
}
#[doc = "`read()` method returns [`pinmuxgrp_generalio9::R`](R) reader structure"]
impl crate::Readable for PinmuxgrpGeneralio9Spec {}
#[doc = "`write(|w| ..)` method takes [`pinmuxgrp_generalio9::W`](W) writer structure"]
impl crate::Writable for PinmuxgrpGeneralio9Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets pinmuxgrp_GENERALIO9 to value 0"]
impl crate::Resettable for PinmuxgrpGeneralio9Spec {
    const RESET_VALUE: u32 = 0;
}
