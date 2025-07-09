// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `pinmuxgrp_GPLINMUX58` reader"]
pub type R = crate::R<PinmuxgrpGplinmux58Spec>;
#[doc = "Register `pinmuxgrp_GPLINMUX58` writer"]
pub type W = crate::W<PinmuxgrpGplinmux58Spec>;
#[doc = "Field `sel` reader - Select source for GPIO/LoanIO 58. 0 : Source for GPIO/LoanIO 58 is GENERALIO10. 1 : Source for GPIO/LoanIO 58 is MIXED2IO4."]
pub type SelR = crate::BitReader;
#[doc = "Field `sel` writer - Select source for GPIO/LoanIO 58. 0 : Source for GPIO/LoanIO 58 is GENERALIO10. 1 : Source for GPIO/LoanIO 58 is MIXED2IO4."]
pub type SelW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Select source for GPIO/LoanIO 58. 0 : Source for GPIO/LoanIO 58 is GENERALIO10. 1 : Source for GPIO/LoanIO 58 is MIXED2IO4."]
    #[inline(always)]
    pub fn sel(&self) -> SelR {
        SelR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Select source for GPIO/LoanIO 58. 0 : Source for GPIO/LoanIO 58 is GENERALIO10. 1 : Source for GPIO/LoanIO 58 is MIXED2IO4."]
    #[inline(always)]
    #[must_use]
    pub fn sel(&mut self) -> SelW<PinmuxgrpGplinmux58Spec> {
        SelW::new(self, 0)
    }
}
#[doc = "Some GPIO/LoanIO inputs can be driven by multiple pins. This register selects the input signal for GPIO/LoanIO 58. Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplinmux58::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplinmux58::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PinmuxgrpGplinmux58Spec;
impl crate::RegisterSpec for PinmuxgrpGplinmux58Spec {
    type Ux = u32;
    const OFFSET: u64 = 1440u64;
}
#[doc = "`read()` method returns [`pinmuxgrp_gplinmux58::R`](R) reader structure"]
impl crate::Readable for PinmuxgrpGplinmux58Spec {}
#[doc = "`write(|w| ..)` method takes [`pinmuxgrp_gplinmux58::W`](W) writer structure"]
impl crate::Writable for PinmuxgrpGplinmux58Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets pinmuxgrp_GPLINMUX58 to value 0"]
impl crate::Resettable for PinmuxgrpGplinmux58Spec {
    const RESET_VALUE: u32 = 0;
}
