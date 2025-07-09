// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `pinmuxgrp_GENERALIO4` reader"]
pub type R = crate::R<PinmuxgrpGeneralio4Spec>;
#[doc = "Register `pinmuxgrp_GENERALIO4` writer"]
pub type W = crate::W<PinmuxgrpGeneralio4Spec>;
#[doc = "Field `sel` reader - Select peripheral signals connected trace_d3. 0 : Pin is connected to GPIO/LoanIO number 52. 1 : Pin is connected to Peripheral signal I2C1.SCL. 2 : Pin is connected to Peripheral signal SPIS0.SS0. 3 : Pin is connected to Peripheral signal TRACE.D3."]
pub type SelR = crate::FieldReader;
#[doc = "Field `sel` writer - Select peripheral signals connected trace_d3. 0 : Pin is connected to GPIO/LoanIO number 52. 1 : Pin is connected to Peripheral signal I2C1.SCL. 2 : Pin is connected to Peripheral signal SPIS0.SS0. 3 : Pin is connected to Peripheral signal TRACE.D3."]
pub type SelW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:1 - Select peripheral signals connected trace_d3. 0 : Pin is connected to GPIO/LoanIO number 52. 1 : Pin is connected to Peripheral signal I2C1.SCL. 2 : Pin is connected to Peripheral signal SPIS0.SS0. 3 : Pin is connected to Peripheral signal TRACE.D3."]
    #[inline(always)]
    pub fn sel(&self) -> SelR {
        SelR::new((self.bits & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Select peripheral signals connected trace_d3. 0 : Pin is connected to GPIO/LoanIO number 52. 1 : Pin is connected to Peripheral signal I2C1.SCL. 2 : Pin is connected to Peripheral signal SPIS0.SS0. 3 : Pin is connected to Peripheral signal TRACE.D3."]
    #[inline(always)]
    #[must_use]
    pub fn sel(&mut self) -> SelW<PinmuxgrpGeneralio4Spec> {
        SelW::new(self, 0)
    }
}
#[doc = "This register is used to control the peripherals connected to trace_d3 Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio4::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio4::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PinmuxgrpGeneralio4Spec;
impl crate::RegisterSpec for PinmuxgrpGeneralio4Spec {
    type Ux = u32;
    const OFFSET: u64 = 1168u64;
}
#[doc = "`read()` method returns [`pinmuxgrp_generalio4::R`](R) reader structure"]
impl crate::Readable for PinmuxgrpGeneralio4Spec {}
#[doc = "`write(|w| ..)` method takes [`pinmuxgrp_generalio4::W`](W) writer structure"]
impl crate::Writable for PinmuxgrpGeneralio4Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets pinmuxgrp_GENERALIO4 to value 0"]
impl crate::Resettable for PinmuxgrpGeneralio4Spec {
    const RESET_VALUE: u32 = 0;
}
