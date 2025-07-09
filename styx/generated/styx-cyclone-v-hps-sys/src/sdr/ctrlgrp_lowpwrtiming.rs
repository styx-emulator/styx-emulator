// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ctrlgrp_lowpwrtiming` reader"]
pub type R = crate::R<CtrlgrpLowpwrtimingSpec>;
#[doc = "Register `ctrlgrp_lowpwrtiming` writer"]
pub type W = crate::W<CtrlgrpLowpwrtimingSpec>;
#[doc = "Field `autopdcycles` reader - The number of idle clock cycles after which the controller should place the memory into power-down mode."]
pub type AutopdcyclesR = crate::FieldReader<u16>;
#[doc = "Field `autopdcycles` writer - The number of idle clock cycles after which the controller should place the memory into power-down mode."]
pub type AutopdcyclesW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `clkdisablecycles` reader - Set to a the number of clocks after the execution of an self-refresh to stop the clock. This register is generally set based on PHY design latency and should generally not be changed."]
pub type ClkdisablecyclesR = crate::FieldReader;
#[doc = "Field `clkdisablecycles` writer - Set to a the number of clocks after the execution of an self-refresh to stop the clock. This register is generally set based on PHY design latency and should generally not be changed."]
pub type ClkdisablecyclesW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:15 - The number of idle clock cycles after which the controller should place the memory into power-down mode."]
    #[inline(always)]
    pub fn autopdcycles(&self) -> AutopdcyclesR {
        AutopdcyclesR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:19 - Set to a the number of clocks after the execution of an self-refresh to stop the clock. This register is generally set based on PHY design latency and should generally not be changed."]
    #[inline(always)]
    pub fn clkdisablecycles(&self) -> ClkdisablecyclesR {
        ClkdisablecyclesR::new(((self.bits >> 16) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:15 - The number of idle clock cycles after which the controller should place the memory into power-down mode."]
    #[inline(always)]
    #[must_use]
    pub fn autopdcycles(&mut self) -> AutopdcyclesW<CtrlgrpLowpwrtimingSpec> {
        AutopdcyclesW::new(self, 0)
    }
    #[doc = "Bits 16:19 - Set to a the number of clocks after the execution of an self-refresh to stop the clock. This register is generally set based on PHY design latency and should generally not be changed."]
    #[inline(always)]
    #[must_use]
    pub fn clkdisablecycles(&mut self) -> ClkdisablecyclesW<CtrlgrpLowpwrtimingSpec> {
        ClkdisablecyclesW::new(self, 16)
    }
}
#[doc = "This register controls the behavior of the low power logic in the controller.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ctrlgrp_lowpwrtiming::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ctrlgrp_lowpwrtiming::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CtrlgrpLowpwrtimingSpec;
impl crate::RegisterSpec for CtrlgrpLowpwrtimingSpec {
    type Ux = u32;
    const OFFSET: u64 = 20500u64;
}
#[doc = "`read()` method returns [`ctrlgrp_lowpwrtiming::R`](R) reader structure"]
impl crate::Readable for CtrlgrpLowpwrtimingSpec {}
#[doc = "`write(|w| ..)` method takes [`ctrlgrp_lowpwrtiming::W`](W) writer structure"]
impl crate::Writable for CtrlgrpLowpwrtimingSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ctrlgrp_lowpwrtiming to value 0"]
impl crate::Resettable for CtrlgrpLowpwrtimingSpec {
    const RESET_VALUE: u32 = 0;
}
