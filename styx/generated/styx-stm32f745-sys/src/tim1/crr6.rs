// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CRR6` reader"]
pub type R = crate::R<Crr6Spec>;
#[doc = "Register `CRR6` writer"]
pub type W = crate::W<Crr6Spec>;
#[doc = "Field `CCR6` reader - Capture/Compare 6 value"]
pub type Ccr6R = crate::FieldReader<u16>;
#[doc = "Field `CCR6` writer - Capture/Compare 6 value"]
pub type Ccr6W<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Capture/Compare 6 value"]
    #[inline(always)]
    pub fn ccr6(&self) -> Ccr6R {
        Ccr6R::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Capture/Compare 6 value"]
    #[inline(always)]
    #[must_use]
    pub fn ccr6(&mut self) -> Ccr6W<Crr6Spec> {
        Ccr6W::new(self, 0)
    }
}
#[doc = "capture/compare register 6\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`crr6::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`crr6::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Crr6Spec;
impl crate::RegisterSpec for Crr6Spec {
    type Ux = u32;
    const OFFSET: u64 = 92u64;
}
#[doc = "`read()` method returns [`crr6::R`](R) reader structure"]
impl crate::Readable for Crr6Spec {}
#[doc = "`write(|w| ..)` method takes [`crr6::W`](W) writer structure"]
impl crate::Writable for Crr6Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CRR6 to value 0"]
impl crate::Resettable for Crr6Spec {
    const RESET_VALUE: u32 = 0;
}
