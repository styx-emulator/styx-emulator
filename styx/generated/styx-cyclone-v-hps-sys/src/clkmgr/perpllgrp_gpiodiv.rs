// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `perpllgrp_gpiodiv` reader"]
pub type R = crate::R<PerpllgrpGpiodivSpec>;
#[doc = "Register `perpllgrp_gpiodiv` writer"]
pub type W = crate::W<PerpllgrpGpiodivSpec>;
#[doc = "Field `gpiodbclk` reader - The gpio_db_clk is divided down from the periph_base_clk by the value plus one specified in this field. The value 0 (divide by 1) is illegal. A value of 1 indicates divide by 2, 2 divide by 3, etc."]
pub type GpiodbclkR = crate::FieldReader<u32>;
#[doc = "Field `gpiodbclk` writer - The gpio_db_clk is divided down from the periph_base_clk by the value plus one specified in this field. The value 0 (divide by 1) is illegal. A value of 1 indicates divide by 2, 2 divide by 3, etc."]
pub type GpiodbclkW<'a, REG> = crate::FieldWriter<'a, REG, 24, u32>;
impl R {
    #[doc = "Bits 0:23 - The gpio_db_clk is divided down from the periph_base_clk by the value plus one specified in this field. The value 0 (divide by 1) is illegal. A value of 1 indicates divide by 2, 2 divide by 3, etc."]
    #[inline(always)]
    pub fn gpiodbclk(&self) -> GpiodbclkR {
        GpiodbclkR::new(self.bits & 0x00ff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:23 - The gpio_db_clk is divided down from the periph_base_clk by the value plus one specified in this field. The value 0 (divide by 1) is illegal. A value of 1 indicates divide by 2, 2 divide by 3, etc."]
    #[inline(always)]
    #[must_use]
    pub fn gpiodbclk(&mut self) -> GpiodbclkW<PerpllgrpGpiodivSpec> {
        GpiodbclkW::new(self, 0)
    }
}
#[doc = "Contains a field that controls the clock divider for the GPIO De-bounce clock. Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`perpllgrp_gpiodiv::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`perpllgrp_gpiodiv::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PerpllgrpGpiodivSpec;
impl crate::RegisterSpec for PerpllgrpGpiodivSpec {
    type Ux = u32;
    const OFFSET: u64 = 168u64;
}
#[doc = "`read()` method returns [`perpllgrp_gpiodiv::R`](R) reader structure"]
impl crate::Readable for PerpllgrpGpiodivSpec {}
#[doc = "`write(|w| ..)` method takes [`perpllgrp_gpiodiv::W`](W) writer structure"]
impl crate::Writable for PerpllgrpGpiodivSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets perpllgrp_gpiodiv to value 0x01"]
impl crate::Resettable for PerpllgrpGpiodivSpec {
    const RESET_VALUE: u32 = 0x01;
}
