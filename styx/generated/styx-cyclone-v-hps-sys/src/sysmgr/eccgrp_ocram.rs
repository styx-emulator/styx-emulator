// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `eccgrp_ocram` reader"]
pub type R = crate::R<EccgrpOcramSpec>;
#[doc = "Register `eccgrp_ocram` writer"]
pub type W = crate::W<EccgrpOcramSpec>;
#[doc = "Field `en` reader - Enable ECC for On-chip RAM"]
pub type EnR = crate::BitReader;
#[doc = "Field `en` writer - Enable ECC for On-chip RAM"]
pub type EnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `injs` reader - Changing this bit from zero to one injects a single, correctable error into the On-chip RAM. This only injects one error into the On-chip RAM."]
pub type InjsR = crate::BitReader;
#[doc = "Field `injs` writer - Changing this bit from zero to one injects a single, correctable error into the On-chip RAM. This only injects one error into the On-chip RAM."]
pub type InjsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `injd` reader - Changing this bit from zero to one injects a double, non-correctable error into the On-chip RAM. This only injects one double bit error into the On-chip RAM."]
pub type InjdR = crate::BitReader;
#[doc = "Field `injd` writer - Changing this bit from zero to one injects a double, non-correctable error into the On-chip RAM. This only injects one double bit error into the On-chip RAM."]
pub type InjdW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `serr` reader - This bit is an interrupt status bit for On-chip RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in On-chip RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type SerrR = crate::BitReader;
#[doc = "Field `serr` writer - This bit is an interrupt status bit for On-chip RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in On-chip RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type SerrW<'a, REG> = crate::BitWriter1C<'a, REG>;
#[doc = "Field `derr` reader - This bit is an interrupt status bit for On-chip RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in On-chip RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type DerrR = crate::BitReader;
#[doc = "Field `derr` writer - This bit is an interrupt status bit for On-chip RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in On-chip RAM. Software needs to write 1 into this bit to clear the interrupt status."]
pub type DerrW<'a, REG> = crate::BitWriter1C<'a, REG>;
impl R {
    #[doc = "Bit 0 - Enable ECC for On-chip RAM"]
    #[inline(always)]
    pub fn en(&self) -> EnR {
        EnR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Changing this bit from zero to one injects a single, correctable error into the On-chip RAM. This only injects one error into the On-chip RAM."]
    #[inline(always)]
    pub fn injs(&self) -> InjsR {
        InjsR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Changing this bit from zero to one injects a double, non-correctable error into the On-chip RAM. This only injects one double bit error into the On-chip RAM."]
    #[inline(always)]
    pub fn injd(&self) -> InjdR {
        InjdR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - This bit is an interrupt status bit for On-chip RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in On-chip RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    pub fn serr(&self) -> SerrR {
        SerrR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - This bit is an interrupt status bit for On-chip RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in On-chip RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    pub fn derr(&self) -> DerrR {
        DerrR::new(((self.bits >> 4) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Enable ECC for On-chip RAM"]
    #[inline(always)]
    #[must_use]
    pub fn en(&mut self) -> EnW<EccgrpOcramSpec> {
        EnW::new(self, 0)
    }
    #[doc = "Bit 1 - Changing this bit from zero to one injects a single, correctable error into the On-chip RAM. This only injects one error into the On-chip RAM."]
    #[inline(always)]
    #[must_use]
    pub fn injs(&mut self) -> InjsW<EccgrpOcramSpec> {
        InjsW::new(self, 1)
    }
    #[doc = "Bit 2 - Changing this bit from zero to one injects a double, non-correctable error into the On-chip RAM. This only injects one double bit error into the On-chip RAM."]
    #[inline(always)]
    #[must_use]
    pub fn injd(&mut self) -> InjdW<EccgrpOcramSpec> {
        InjdW::new(self, 2)
    }
    #[doc = "Bit 3 - This bit is an interrupt status bit for On-chip RAM ECC single, correctable error. It is set by hardware when single, correctable error occurs in On-chip RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    #[must_use]
    pub fn serr(&mut self) -> SerrW<EccgrpOcramSpec> {
        SerrW::new(self, 3)
    }
    #[doc = "Bit 4 - This bit is an interrupt status bit for On-chip RAM ECC double bit, non-correctable error. It is set by hardware when double bit, non-correctable error occurs in On-chip RAM. Software needs to write 1 into this bit to clear the interrupt status."]
    #[inline(always)]
    #[must_use]
    pub fn derr(&mut self) -> DerrW<EccgrpOcramSpec> {
        DerrW::new(self, 4)
    }
}
#[doc = "This register is used to enable ECC on the On-chip RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`eccgrp_ocram::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`eccgrp_ocram::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct EccgrpOcramSpec;
impl crate::RegisterSpec for EccgrpOcramSpec {
    type Ux = u32;
    const OFFSET: u64 = 324u64;
}
#[doc = "`read()` method returns [`eccgrp_ocram::R`](R) reader structure"]
impl crate::Readable for EccgrpOcramSpec {}
#[doc = "`write(|w| ..)` method takes [`eccgrp_ocram::W`](W) writer structure"]
impl crate::Writable for EccgrpOcramSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0x18;
}
#[doc = "`reset()` method sets eccgrp_ocram to value 0"]
impl crate::Resettable for EccgrpOcramSpec {
    const RESET_VALUE: u32 = 0;
}
