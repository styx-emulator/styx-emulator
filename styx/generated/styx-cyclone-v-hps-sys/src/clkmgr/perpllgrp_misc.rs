// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `perpllgrp_misc` reader"]
pub type R = crate::R<PerpllgrpMiscSpec>;
#[doc = "Register `perpllgrp_misc` writer"]
pub type W = crate::W<PerpllgrpMiscSpec>;
#[doc = "Field `bwadjen` reader - If set to 1, the Loop Bandwidth Adjust value comes from the Loop Bandwidth Adjust field. If set to 0, the Loop Bandwidth Adjust value equals the M field divided by 2 value of the VCO Control Register. The M divided by 2 is the upper 12 bits (12:1) of the M field in the VCO register."]
pub type BwadjenR = crate::BitReader;
#[doc = "Field `bwadjen` writer - If set to 1, the Loop Bandwidth Adjust value comes from the Loop Bandwidth Adjust field. If set to 0, the Loop Bandwidth Adjust value equals the M field divided by 2 value of the VCO Control Register. The M divided by 2 is the upper 12 bits (12:1) of the M field in the VCO register."]
pub type BwadjenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `bwadj` reader - Provides Loop Bandwidth Adjust value."]
pub type BwadjR = crate::FieldReader<u16>;
#[doc = "Field `bwadj` writer - Provides Loop Bandwidth Adjust value."]
pub type BwadjW<'a, REG> = crate::FieldWriter<'a, REG, 12, u16>;
#[doc = "Field `fasten` reader - Enables fast locking circuit."]
pub type FastenR = crate::BitReader;
#[doc = "Field `fasten` writer - Enables fast locking circuit."]
pub type FastenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `saten` reader - Enables saturation behavior."]
pub type SatenR = crate::BitReader;
#[doc = "Field `saten` writer - Enables saturation behavior."]
pub type SatenW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - If set to 1, the Loop Bandwidth Adjust value comes from the Loop Bandwidth Adjust field. If set to 0, the Loop Bandwidth Adjust value equals the M field divided by 2 value of the VCO Control Register. The M divided by 2 is the upper 12 bits (12:1) of the M field in the VCO register."]
    #[inline(always)]
    pub fn bwadjen(&self) -> BwadjenR {
        BwadjenR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 1:12 - Provides Loop Bandwidth Adjust value."]
    #[inline(always)]
    pub fn bwadj(&self) -> BwadjR {
        BwadjR::new(((self.bits >> 1) & 0x0fff) as u16)
    }
    #[doc = "Bit 13 - Enables fast locking circuit."]
    #[inline(always)]
    pub fn fasten(&self) -> FastenR {
        FastenR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bit 14 - Enables saturation behavior."]
    #[inline(always)]
    pub fn saten(&self) -> SatenR {
        SatenR::new(((self.bits >> 14) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - If set to 1, the Loop Bandwidth Adjust value comes from the Loop Bandwidth Adjust field. If set to 0, the Loop Bandwidth Adjust value equals the M field divided by 2 value of the VCO Control Register. The M divided by 2 is the upper 12 bits (12:1) of the M field in the VCO register."]
    #[inline(always)]
    #[must_use]
    pub fn bwadjen(&mut self) -> BwadjenW<PerpllgrpMiscSpec> {
        BwadjenW::new(self, 0)
    }
    #[doc = "Bits 1:12 - Provides Loop Bandwidth Adjust value."]
    #[inline(always)]
    #[must_use]
    pub fn bwadj(&mut self) -> BwadjW<PerpllgrpMiscSpec> {
        BwadjW::new(self, 1)
    }
    #[doc = "Bit 13 - Enables fast locking circuit."]
    #[inline(always)]
    #[must_use]
    pub fn fasten(&mut self) -> FastenW<PerpllgrpMiscSpec> {
        FastenW::new(self, 13)
    }
    #[doc = "Bit 14 - Enables saturation behavior."]
    #[inline(always)]
    #[must_use]
    pub fn saten(&mut self) -> SatenW<PerpllgrpMiscSpec> {
        SatenW::new(self, 14)
    }
}
#[doc = "Contains VCO control signals and other PLL control signals need to be controllable through register. Fields are only reset by a cold reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`perpllgrp_misc::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`perpllgrp_misc::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PerpllgrpMiscSpec;
impl crate::RegisterSpec for PerpllgrpMiscSpec {
    type Ux = u32;
    const OFFSET: u64 = 132u64;
}
#[doc = "`read()` method returns [`perpllgrp_misc::R`](R) reader structure"]
impl crate::Readable for PerpllgrpMiscSpec {}
#[doc = "`write(|w| ..)` method takes [`perpllgrp_misc::W`](W) writer structure"]
impl crate::Writable for PerpllgrpMiscSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets perpllgrp_misc to value 0x4002"]
impl crate::Resettable for PerpllgrpMiscSpec {
    const RESET_VALUE: u32 = 0x4002;
}
