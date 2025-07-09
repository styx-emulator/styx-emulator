// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_dramtiming4` reader"]
pub type R = crate::R<CtrlgrpDramtiming4Spec>;
#[doc = "Register `ctrlgrp_dramtiming4` writer"]
pub type W = crate::W<CtrlgrpDramtiming4Spec>;
#[doc = "Field `selfrfshexit` reader - The self refresh exit cycles, tXS."]
pub type SelfrfshexitR = crate::FieldReader<u16>;
#[doc = "Field `selfrfshexit` writer - The self refresh exit cycles, tXS."]
pub type SelfrfshexitW<'a, REG> = crate::FieldWriter<'a, REG, 10, u16>;
#[doc = "Field `pwrdownexit` reader - The power down exit cycles, tXPDLL."]
pub type PwrdownexitR = crate::FieldReader<u16>;
#[doc = "Field `pwrdownexit` writer - The power down exit cycles, tXPDLL."]
pub type PwrdownexitW<'a, REG> = crate::FieldWriter<'a, REG, 10, u16>;
#[doc = "Field `minpwrsavecycles` reader - The minimum number of cycles to stay in a low power state. This applies to both power down and self-refresh and should be set to the greater of tPD and tCKESR."]
pub type MinpwrsavecyclesR = crate::FieldReader;
#[doc = "Field `minpwrsavecycles` writer - The minimum number of cycles to stay in a low power state. This applies to both power down and self-refresh and should be set to the greater of tPD and tCKESR."]
pub type MinpwrsavecyclesW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:9 - The self refresh exit cycles, tXS."]
    #[inline(always)]
    pub fn selfrfshexit(&self) -> SelfrfshexitR {
        SelfrfshexitR::new((self.bits & 0x03ff) as u16)
    }
    #[doc = "Bits 10:19 - The power down exit cycles, tXPDLL."]
    #[inline(always)]
    pub fn pwrdownexit(&self) -> PwrdownexitR {
        PwrdownexitR::new(((self.bits >> 10) & 0x03ff) as u16)
    }
    #[doc = "Bits 20:23 - The minimum number of cycles to stay in a low power state. This applies to both power down and self-refresh and should be set to the greater of tPD and tCKESR."]
    #[inline(always)]
    pub fn minpwrsavecycles(&self) -> MinpwrsavecyclesR {
        MinpwrsavecyclesR::new(((self.bits >> 20) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:9 - The self refresh exit cycles, tXS."]
    #[inline(always)]
    #[must_use]
    pub fn selfrfshexit(&mut self) -> SelfrfshexitW<CtrlgrpDramtiming4Spec> {
        SelfrfshexitW::new(self, 0)
    }
    #[doc = "Bits 10:19 - The power down exit cycles, tXPDLL."]
    #[inline(always)]
    #[must_use]
    pub fn pwrdownexit(&mut self) -> PwrdownexitW<CtrlgrpDramtiming4Spec> {
        PwrdownexitW::new(self, 10)
    }
    #[doc = "Bits 20:23 - The minimum number of cycles to stay in a low power state. This applies to both power down and self-refresh and should be set to the greater of tPD and tCKESR."]
    #[inline(always)]
    #[must_use]
    pub fn minpwrsavecycles(&mut self) -> MinpwrsavecyclesW<CtrlgrpDramtiming4Spec> {
        MinpwrsavecyclesW::new(self, 20)
    }
}
#[doc = "This register implements JEDEC standardized timing parameters. It should be programmed in clock cycles, for the value specified by the memory vendor.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_dramtiming4::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_dramtiming4::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpDramtiming4Spec;
impl crate::RegisterSpec for CtrlgrpDramtiming4Spec {
    type Ux = u32;
    const OFFSET: u64 = 20496u64;
}
#[doc = "`read()` method returns [`ctrlgrp_dramtiming4::R`](R) reader structure"]
impl crate::Readable for CtrlgrpDramtiming4Spec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_dramtiming4::W`](W) writer structure"]
impl crate::Writable for CtrlgrpDramtiming4Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_dramtiming4 to value 0"]
impl crate::Resettable for CtrlgrpDramtiming4Spec {
    const RESET_VALUE: u32 = 0;
}
