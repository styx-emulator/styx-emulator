// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `perpllgrp_perbaseclk` reader"]
pub type R = crate::R<PerpllgrpPerbaseclkSpec>;
#[doc = "Register `perpllgrp_perbaseclk` writer"]
pub type W = crate::W<PerpllgrpPerbaseclkSpec>;
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
    pub fn cnt(&mut self) -> CntW<PerpllgrpPerbaseclkSpec> {
        CntW::new(self, 0)
    }
}
#[doc = "Contains settings that control clock periph_base_clk generated from the C4 output of the Peripheral PLL. Only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`perpllgrp_perbaseclk::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`perpllgrp_perbaseclk::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PerpllgrpPerbaseclkSpec;
impl crate::RegisterSpec for PerpllgrpPerbaseclkSpec {
    type Ux = u32;
    const OFFSET: u64 = 152u64;
}
#[doc = "`read()` method returns [`perpllgrp_perbaseclk::R`](R) reader structure"]
impl crate::Readable for PerpllgrpPerbaseclkSpec {}
#[doc = "`write(|w| ..)` method takes [`perpllgrp_perbaseclk::W`](W) writer structure"]
impl crate::Writable for PerpllgrpPerbaseclkSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets perpllgrp_perbaseclk to value 0x01"]
impl crate::Resettable for PerpllgrpPerbaseclkSpec {
    const RESET_VALUE: u32 = 0x01;
}
