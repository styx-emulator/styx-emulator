// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `pinmuxgrp_GPLMUX66` reader"]
pub type R = crate::R<PinmuxgrpGplmux66Spec>;
#[doc = "Register `pinmuxgrp_GPLMUX66` writer"]
pub type W = crate::W<PinmuxgrpGplmux66Spec>;
#[doc = "Field `sel` reader - Select source for GPIO/LoanIO 66. 0 : LoanIO 66 controls GPIO/LOANIO\\[66\\]
output and output enable signals. 1 : GPIO 66 controls GPIO/LOANI\\[66\\]
output and output enable signals."]
pub type SelR = crate::BitReader;
#[doc = "Field `sel` writer - Select source for GPIO/LoanIO 66. 0 : LoanIO 66 controls GPIO/LOANIO\\[66\\]
output and output enable signals. 1 : GPIO 66 controls GPIO/LOANI\\[66\\]
output and output enable signals."]
pub type SelW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Select source for GPIO/LoanIO 66. 0 : LoanIO 66 controls GPIO/LOANIO\\[66\\]
output and output enable signals. 1 : GPIO 66 controls GPIO/LOANI\\[66\\]
output and output enable signals."]
    #[inline(always)]
    pub fn sel(&self) -> SelR {
        SelR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Select source for GPIO/LoanIO 66. 0 : LoanIO 66 controls GPIO/LOANIO\\[66\\]
output and output enable signals. 1 : GPIO 66 controls GPIO/LOANI\\[66\\]
output and output enable signals."]
    #[inline(always)]
    #[must_use]
    pub fn sel(&mut self) -> SelW<PinmuxgrpGplmux66Spec> {
        SelW::new(self, 0)
    }
}
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO66 and LoanIO66. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux66::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux66::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PinmuxgrpGplmux66Spec;
impl crate::RegisterSpec for PinmuxgrpGplmux66Spec {
    type Ux = u32;
    const OFFSET: u64 = 1756u64;
}
#[doc = "`read()` method returns [`pinmuxgrp_gplmux66::R`](R) reader structure"]
impl crate::Readable for PinmuxgrpGplmux66Spec {}
#[doc = "`write(|w| ..)` method takes [`pinmuxgrp_gplmux66::W`](W) writer structure"]
impl crate::Writable for PinmuxgrpGplmux66Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets pinmuxgrp_GPLMUX66 to value 0"]
impl crate::Resettable for PinmuxgrpGplmux66Spec {
    const RESET_VALUE: u32 = 0;
}
