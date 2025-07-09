// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `pinmuxgrp_GENERALIO29` reader"]
pub type R = crate::R<PinmuxgrpGeneralio29Spec>;
#[doc = "Register `pinmuxgrp_GENERALIO29` writer"]
pub type W = crate::W<PinmuxgrpGeneralio29Spec>;
#[doc = "Field `sel` reader - Select peripheral signals connected spis0_mosi. 0 : Pin is connected to GPIO/LoanIO number 68. 1 : Pin is connected to Peripheral signal not applicable. 2 : Pin is connected to Peripheral signal not applicable. 3 : Pin is connected to Peripheral signal SPIS0.MOSI."]
pub type SelR = crate::FieldReader;
#[doc = "Field `sel` writer - Select peripheral signals connected spis0_mosi. 0 : Pin is connected to GPIO/LoanIO number 68. 1 : Pin is connected to Peripheral signal not applicable. 2 : Pin is connected to Peripheral signal not applicable. 3 : Pin is connected to Peripheral signal SPIS0.MOSI."]
pub type SelW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:1 - Select peripheral signals connected spis0_mosi. 0 : Pin is connected to GPIO/LoanIO number 68. 1 : Pin is connected to Peripheral signal not applicable. 2 : Pin is connected to Peripheral signal not applicable. 3 : Pin is connected to Peripheral signal SPIS0.MOSI."]
    #[inline(always)]
    pub fn sel(&self) -> SelR {
        SelR::new((self.bits & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - Select peripheral signals connected spis0_mosi. 0 : Pin is connected to GPIO/LoanIO number 68. 1 : Pin is connected to Peripheral signal not applicable. 2 : Pin is connected to Peripheral signal not applicable. 3 : Pin is connected to Peripheral signal SPIS0.MOSI."]
    #[inline(always)]
    #[must_use]
    pub fn sel(&mut self) -> SelW<PinmuxgrpGeneralio29Spec> {
        SelW::new(self, 0)
    }
}
#[doc = "This register is used to control the peripherals connected to spis0_mosi Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_generalio29::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_generalio29::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PinmuxgrpGeneralio29Spec;
impl crate::RegisterSpec for PinmuxgrpGeneralio29Spec {
    type Ux = u32;
    const OFFSET: u64 = 1268u64;
}
#[doc = "`read()` method returns [`pinmuxgrp_generalio29::R`](R) reader structure"]
impl crate::Readable for PinmuxgrpGeneralio29Spec {}
#[doc = "`write(|w| ..)` method takes [`pinmuxgrp_generalio29::W`](W) writer structure"]
impl crate::Writable for PinmuxgrpGeneralio29Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets pinmuxgrp_GENERALIO29 to value 0"]
impl crate::Resettable for PinmuxgrpGeneralio29Spec {
    const RESET_VALUE: u32 = 0;
}
