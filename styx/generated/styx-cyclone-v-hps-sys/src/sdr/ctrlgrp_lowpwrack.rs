// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_lowpwrack` reader"]
pub type R = crate::R<CtrlgrpLowpwrackSpec>;
#[doc = "Register `ctrlgrp_lowpwrack` writer"]
pub type W = crate::W<CtrlgrpLowpwrackSpec>;
#[doc = "Field `deeppwrdnack` reader - This bit is set to a one after a deep power down has been executed"]
pub type DeeppwrdnackR = crate::BitReader;
#[doc = "Field `deeppwrdnack` writer - This bit is set to a one after a deep power down has been executed"]
pub type DeeppwrdnackW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `selfrfshack` reader - This bit is a one to indicate that the controller is in a self-refresh state."]
pub type SelfrfshackR = crate::BitReader;
#[doc = "Field `selfrfshack` writer - This bit is a one to indicate that the controller is in a self-refresh state."]
pub type SelfrfshackW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - This bit is set to a one after a deep power down has been executed"]
    #[inline(always)]
    pub fn deeppwrdnack(&self) -> DeeppwrdnackR {
        DeeppwrdnackR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - This bit is a one to indicate that the controller is in a self-refresh state."]
    #[inline(always)]
    pub fn selfrfshack(&self) -> SelfrfshackR {
        SelfrfshackR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - This bit is set to a one after a deep power down has been executed"]
    #[inline(always)]
    #[must_use]
    pub fn deeppwrdnack(&mut self) -> DeeppwrdnackW<CtrlgrpLowpwrackSpec> {
        DeeppwrdnackW::new(self, 0)
    }
    #[doc = "Bit 1 - This bit is a one to indicate that the controller is in a self-refresh state."]
    #[inline(always)]
    #[must_use]
    pub fn selfrfshack(&mut self) -> SelfrfshackW<CtrlgrpLowpwrackSpec> {
        SelfrfshackW::new(self, 1)
    }
}
#[doc = "This register gives the status of the power down commands requested by the Low Power Control register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_lowpwrack::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_lowpwrack::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpLowpwrackSpec;
impl crate::RegisterSpec for CtrlgrpLowpwrackSpec {
    type Ux = u32;
    const OFFSET: u64 = 20568u64;
}
#[doc = "`read()` method returns [`ctrlgrp_lowpwrack::R`](R) reader structure"]
impl crate::Readable for CtrlgrpLowpwrackSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_lowpwrack::W`](W) writer structure"]
impl crate::Writable for CtrlgrpLowpwrackSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_lowpwrack to value 0"]
impl crate::Resettable for CtrlgrpLowpwrackSpec {
    const RESET_VALUE: u32 = 0;
}
