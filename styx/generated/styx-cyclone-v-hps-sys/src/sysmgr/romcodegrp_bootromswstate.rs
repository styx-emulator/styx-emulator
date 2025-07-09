// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `romcodegrp_bootromswstate` reader"]
pub type R = crate::R<RomcodegrpBootromswstateSpec>;
#[doc = "Register `romcodegrp_bootromswstate` writer"]
pub type W = crate::W<RomcodegrpBootromswstateSpec>;
#[doc = "Field `value` reader - Reserved for Boot ROM use."]
pub type ValueR = crate::FieldReader<u32>;
#[doc = "Field `value` writer - Reserved for Boot ROM use."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Reserved for Boot ROM use."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Reserved for Boot ROM use."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<RomcodegrpBootromswstateSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "32-bits general purpose register used by the Boot ROM code. Actual usage is defined in the Boot ROM source code.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`romcodegrp_bootromswstate::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`romcodegrp_bootromswstate::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct RomcodegrpBootromswstateSpec;
impl crate::RegisterSpec for RomcodegrpBootromswstateSpec {
    type Ux = u32;
    const OFFSET: u64 = 208u64;
}
#[doc = "`read()` method returns [`romcodegrp_bootromswstate::R`](R) reader structure"]
impl crate::Readable for RomcodegrpBootromswstateSpec {}
#[doc = "`write(|w| ..)` method takes [`romcodegrp_bootromswstate::W`](W) writer structure"]
impl crate::Writable for RomcodegrpBootromswstateSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets romcodegrp_bootromswstate to value 0"]
impl crate::Resettable for RomcodegrpBootromswstateSpec {
    const RESET_VALUE: u32 = 0;
}
