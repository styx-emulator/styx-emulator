// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `perpllgrp_emac1clk` reader"]
pub type R = crate::R<PerpllgrpEmac1clkSpec>;
#[doc = "Register `perpllgrp_emac1clk` writer"]
pub type W = crate::W<PerpllgrpEmac1clkSpec>;
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
    pub fn cnt(&mut self) -> CntW<PerpllgrpEmac1clkSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Contains settings that control clock emac1_clk generated from the C1 output of the Peripheral PLL. Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`perpllgrp_emac1clk::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`perpllgrp_emac1clk::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PerpllgrpEmac1clkSpec;
impl crate::RegisterSpec for PerpllgrpEmac1clkSpec {
    type Ux = u32;
    const OFFSET: u64 = 140u64;
}
#[doc = "`read()` method returns [`perpllgrp_emac1clk::R`](R) reader structure"]
impl crate::Readable for PerpllgrpEmac1clkSpec {}
#[doc = "`write(|w| ..)` method takes [`perpllgrp_emac1clk::W`](W) writer structure"]
impl crate::Writable for PerpllgrpEmac1clkSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets perpllgrp_emac1clk to value 0x01"]
impl crate::Resettable for PerpllgrpEmac1clkSpec {
    const RESET_VALUE: u32 = 0x01;
}
