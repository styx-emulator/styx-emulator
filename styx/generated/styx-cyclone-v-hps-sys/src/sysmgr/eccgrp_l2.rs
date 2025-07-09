// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `eccgrp_l2` reader"]
pub type R = crate::R<EccgrpL2Spec>;
#[doc = "Register `eccgrp_l2` writer"]
pub type W = crate::W<EccgrpL2Spec>;
#[doc = "Field `en` reader - Enable ECC for L2 Data RAM"]
pub type EnR = crate::BitReader;
#[doc = "Field `en` writer - Enable ECC for L2 Data RAM"]
pub type EnW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `injs` reader - Changing this bit from zero to one injects a single, correctable error into the L2 Data RAM. This only injects one error into the L2 Data RAM."]
pub type InjsR = crate::BitReader;
#[doc = "Field `injs` writer - Changing this bit from zero to one injects a single, correctable error into the L2 Data RAM. This only injects one error into the L2 Data RAM."]
pub type InjsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `injd` reader - Changing this bit from zero to one injects a double, non-correctable error into the L2 Data RAM. This only injects one double bit error into the L2 Data RAM."]
pub type InjdR = crate::BitReader;
#[doc = "Field `injd` writer - Changing this bit from zero to one injects a double, non-correctable error into the L2 Data RAM. This only injects one double bit error into the L2 Data RAM."]
pub type InjdW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Enable ECC for L2 Data RAM"]
    #[inline(always)]
    pub fn en(&self) -> EnR {
        EnR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Changing this bit from zero to one injects a single, correctable error into the L2 Data RAM. This only injects one error into the L2 Data RAM."]
    #[inline(always)]
    pub fn injs(&self) -> InjsR {
        InjsR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Changing this bit from zero to one injects a double, non-correctable error into the L2 Data RAM. This only injects one double bit error into the L2 Data RAM."]
    #[inline(always)]
    pub fn injd(&self) -> InjdR {
        InjdR::new(((self.bits >> 2) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Enable ECC for L2 Data RAM"]
    #[inline(always)]
    #[must_use]
    pub fn en(&mut self) -> EnW<EccgrpL2Spec> {
        EnW::new(self, 0)
    }
    #[doc = "Bit 1 - Changing this bit from zero to one injects a single, correctable error into the L2 Data RAM. This only injects one error into the L2 Data RAM."]
    #[inline(always)]
    #[must_use]
    pub fn injs(&mut self) -> InjsW<EccgrpL2Spec> {
        InjsW::new(self, 1)
    }
    #[doc = "Bit 2 - Changing this bit from zero to one injects a double, non-correctable error into the L2 Data RAM. This only injects one double bit error into the L2 Data RAM."]
    #[inline(always)]
    #[must_use]
    pub fn injd(&mut self) -> InjdW<EccgrpL2Spec> {
        InjdW::new(self, 2)
    }
}
#[doc = "This register is used to enable ECC on the L2 Data RAM. ECC errors can be injected into the write path using bits in this register. This register contains interrupt status of the ECC single/double bit error. Only reset by a cold reset (ignores warm reset).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`eccgrp_l2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`eccgrp_l2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct EccgrpL2Spec;
impl crate::RegisterSpec for EccgrpL2Spec {
    type Ux = u32;
    const OFFSET: u64 = 320u64;
}
#[doc = "`read()` method returns [`eccgrp_l2::R`](R) reader structure"]
impl crate::Readable for EccgrpL2Spec {}
#[doc = "`write(|w| ..)` method takes [`eccgrp_l2::W`](W) writer structure"]
impl crate::Writable for EccgrpL2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets eccgrp_l2 to value 0"]
impl crate::Resettable for EccgrpL2Spec {
    const RESET_VALUE: u32 = 0;
}
