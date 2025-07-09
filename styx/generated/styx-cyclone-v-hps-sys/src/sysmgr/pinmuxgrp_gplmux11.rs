// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `pinmuxgrp_GPLMUX11` reader"]
pub type R = crate::R<PinmuxgrpGplmux11Spec>;
#[doc = "Register `pinmuxgrp_GPLMUX11` writer"]
pub type W = crate::W<PinmuxgrpGplmux11Spec>;
#[doc = "Field `sel` reader - Select source for GPIO/LoanIO 11. 0 : LoanIO 11 controls GPIO/LOANIO\\[11\\]
output and output enable signals. 1 : GPIO 11 controls GPIO/LOANI\\[11\\]
output and output enable signals."]
pub type SelR = crate::BitReader;
#[doc = "Field `sel` writer - Select source for GPIO/LoanIO 11. 0 : LoanIO 11 controls GPIO/LOANIO\\[11\\]
output and output enable signals. 1 : GPIO 11 controls GPIO/LOANI\\[11\\]
output and output enable signals."]
pub type SelW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Select source for GPIO/LoanIO 11. 0 : LoanIO 11 controls GPIO/LOANIO\\[11\\]
output and output enable signals. 1 : GPIO 11 controls GPIO/LOANI\\[11\\]
output and output enable signals."]
    #[inline(always)]
    pub fn sel(&self) -> SelR {
        SelR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Select source for GPIO/LoanIO 11. 0 : LoanIO 11 controls GPIO/LOANIO\\[11\\]
output and output enable signals. 1 : GPIO 11 controls GPIO/LOANI\\[11\\]
output and output enable signals."]
    #[inline(always)]
    #[must_use]
    pub fn sel(&mut self) -> SelW<PinmuxgrpGplmux11Spec> {
        SelW::new(self, 0)
    }
}
#[doc = "Selection between GPIO and LoanIO output and output enable for GPIO11 and LoanIO11. These signals drive the Pin Mux. The Pin Mux must be configured to use GPIO/LoanIO in addition to these settings Only reset by a cold reset (ignores warm reset). NOTE: These registers should not be modified after IO configuration.There is no support for dynamically changing the Pin Mux selections.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pinmuxgrp_gplmux11::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pinmuxgrp_gplmux11::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PinmuxgrpGplmux11Spec;
impl crate::RegisterSpec for PinmuxgrpGplmux11Spec {
    type Ux = u32;
    const OFFSET: u64 = 1536u64;
}
#[doc = "`read()` method returns [`pinmuxgrp_gplmux11::R`](R) reader structure"]
impl crate::Readable for PinmuxgrpGplmux11Spec {}
#[doc = "`write(|w| ..)` method takes [`pinmuxgrp_gplmux11::W`](W) writer structure"]
impl crate::Writable for PinmuxgrpGplmux11Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets pinmuxgrp_GPLMUX11 to value 0"]
impl crate::Resettable for PinmuxgrpGplmux11Spec {
    const RESET_VALUE: u32 = 0;
}
