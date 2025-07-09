// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `mainpllgrp_mainqspiclk` reader"]
pub type R = crate::R<MainpllgrpMainqspiclkSpec>;
#[doc = "Register `mainpllgrp_mainqspiclk` writer"]
pub type W = crate::W<MainpllgrpMainqspiclkSpec>;
#[doc = "Field `cnt` reader - Divides the VCO frequency by the value+1 in this field."]
pub type CntR = crate::FieldReader<u16>;
#[doc = "Field `cnt` writer - Divides the VCO frequency by the value+1 in this field."]
pub type CntW<'a, REG> = crate::FieldWriter<'a, REG, 9, u16>;
impl R {
    #[doc = "Bits 0:8 - Divides the VCO frequency by the value+1 in this field."]
    #[inline(always)]
    pub fn cnt(&self) -> CntR {
        CntR::new((self.bits & 0x01ff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:8 - Divides the VCO frequency by the value+1 in this field."]
    #[inline(always)]
    #[must_use]
    pub fn cnt(&mut self) -> CntW<MainpllgrpMainqspiclkSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Contains settings that control clock main_qspi_clk generated from the C3 output of the Main PLL. Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mainpllgrp_mainqspiclk::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mainpllgrp_mainqspiclk::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MainpllgrpMainqspiclkSpec;
impl crate::RegisterSpec for MainpllgrpMainqspiclkSpec {
    type Ux = u32;
    const OFFSET: u64 = 84u64;
}
#[doc = "`read()` method returns [`mainpllgrp_mainqspiclk::R`](R) reader structure"]
impl crate::Readable for MainpllgrpMainqspiclkSpec {}
#[doc = "`write(|w| ..)` method takes [`mainpllgrp_mainqspiclk::W`](W) writer structure"]
impl crate::Writable for MainpllgrpMainqspiclkSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets mainpllgrp_mainqspiclk to value 0x03"]
impl crate::Resettable for MainpllgrpMainqspiclkSpec {
    const RESET_VALUE: u32 = 0x03;
}
