// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `pinmuxgrp_GPLMUX50` reader"]
pub type R = crate::R<PinmuxgrpGplmux50Spec>;
#[doc = "Register `pinmuxgrp_GPLMUX50` writer"]
pub type W = crate::W<PinmuxgrpGplmux50Spec>;
#[doc = "Field `sel` reader - Select source for GPIO/LoanIO 50. 0 : LoanIO 50 controls GPIO/LOANIO\\[50\\]
output and output enable signals. 1 : GPIO 50 controls GPIO/LOANI\\[50\\]
output and output enable signals."]
pub type SelR = crate::BitReader;
#[doc = "Field `sel` writer - Select source for GPIO/LoanIO 50. 0 : LoanIO 50 controls GPIO/LOANIO\\[50\\]
output and output enable signals. 1 : GPIO 50 controls GPIO/LOANI\\[50\\]
output and output enable signals."]
pub type SelW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Select source for GPIO/LoanIO 50. 0 : LoanIO 50 controls GPIO/LOANIO\\[50\\]
output and output enable signals. 1 : GPIO 50 controls GPIO/LOANI\\[50\\]
output and output enable signals."]
    #[inline(always)]
    pub fn sel(&self) -> SelR {
        SelR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Select source for GPIO/LoanIO 50. 0 : LoanIO 50 controls GPIO/LOANIO\\[50\\]
output and output enable signals. 1 : GPIO 50 controls GPIO/LOANI\\[50\\]
output and output enable signals."]
    #[inline(always)]
    #[must_use]
    pub fn sel(&mut self) -> SelW<PinmuxgrpGplmux50Spec> {
        SelW::new(self, 0)
    }
}
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO50 and LoanIO50. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux50::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux50::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PinmuxgrpGplmux50Spec;
impl crate::RegisterSpec for PinmuxgrpGplmux50Spec {
    type Ux = u32;
    const OFFSET: u64 = 1692u64;
}
#[doc = "`read()` method returns [`pinmuxgrp_gplmux50::R`](R) reader structure"]
impl crate::Readable for PinmuxgrpGplmux50Spec {}
#[doc = "`write(|w| ..)` method takes [`pinmuxgrp_gplmux50::W`](W) writer structure"]
impl crate::Writable for PinmuxgrpGplmux50Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets pinmuxgrp_GPLMUX50 to value 0"]
impl crate::Resettable for PinmuxgrpGplmux50Spec {
    const RESET_VALUE: u32 = 0;
}
