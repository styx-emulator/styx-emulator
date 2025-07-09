// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `mainpllgrp_mainclk` reader"]
pub type R = crate::R<MainpllgrpMainclkSpec>;
#[doc = "Register `mainpllgrp_mainclk` writer"]
pub type W = crate::W<MainpllgrpMainclkSpec>;
#[doc = "Field `cnt` reader - Divides the VCO/4 frequency by the value+1 in this field."]
pub type CntR = crate::FieldReader<u16>;
#[doc = "Field `cnt` writer - Divides the VCO/4 frequency by the value+1 in this field."]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 9, u16>;
impl R {
    #[doc = "Bits 0:8 - Divides the VCO/4 frequency by the value+1 in this field."]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new((self.bits & 0x01ff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:8 - Divides the VCO/4 frequency by the value+1 in this field."]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<MainpllgrpMainclkSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Contains settings that control clock main_clk generated from the C1 output of the Main PLL. Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mainpllgrp_mainclk::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mainpllgrp_mainclk::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MainpllgrpMainclkSpec;
impl crate::RegisterSpec for MainpllgrpMainclkSpec {
    type Ux = u32;
    const OFFSET: u64 = 76u64;
}
#[doc = "`read()` method returns [`mainpllgrp_mainclk::R`](R) reader structure"]
impl crate::Readable for MainpllgrpMainclkSpec {}
#[doc = "`write(|w| ..)` method takes [`mainpllgrp_mainclk::W`](W) writer structure"]
impl crate::Writable for MainpllgrpMainclkSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets mainpllgrp_mainclk to value 0"]
impl crate::Resettable for MainpllgrpMainclkSpec {
    const RESET_VALUE: u32 = 0;
}
