// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `VAL` reader"]
pub type R = crate::R<ValSpec>;
#[doc = "Register `VAL` writer"]
pub type W = crate::W<ValSpec>;
#[doc = "Field `CURRENT` reader - Current counter value"]
pub type CurrentR = crate::FieldReader<u32>;
#[doc = "Field `CURRENT` writer - Current counter value"]
pub type CurrentW<'a, REG> = crate::FieldWriter<'a, REG, 24, u32>;
impl R {
    #[doc = "Bits 0:23 - Current counter value"]
    #[inline(always)]
    pub fn current(&self) -> CurrentR {
        CurrentR::new(self.bits & 0x00ff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:23 - Current counter value"]
    #[inline(always)]
    #[must_use]
    pub fn current(&mut self) -> CurrentW<ValSpec> {
        CurrentW::new(self, 0)
    }
}
#[doc = "SysTick current value register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`val::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`val::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ValSpec;
impl crate::RegisterSpec for ValSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`val::R`](R) reader structure"]
impl crate::Readable for ValSpec {}
#[doc = "`write(|w| ..)` method takes [`val::W`](W) writer structure"]
impl crate::Writable for ValSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets VAL to value 0"]
impl crate::Resettable for ValSpec {
    const RESET_VALUE: u32 = 0;
}
