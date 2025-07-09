// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `S1M1AR` reader"]
pub type R = crate::R<S1m1arSpec>;
#[doc = "Register `S1M1AR` writer"]
pub type W = crate::W<S1m1arSpec>;
#[doc = "Field `M1A` reader - Memory 1 address (used in case of Double buffer mode)"]
pub type M1aR = crate::FieldReader<u32>;
#[doc = "Field `M1A` writer - Memory 1 address (used in case of Double buffer mode)"]
pub type M1aW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Memory 1 address (used in case of Double buffer mode)"]
    #[inline(always)]
    pub fn m1a(&self) -> M1aR {
        M1aR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Memory 1 address (used in case of Double buffer mode)"]
    #[inline(always)]
    #[must_use]
    pub fn m1a(&mut self) -> M1aW<S1m1arSpec> {
        M1aW::new(self, 0)
    }
}
#[doc = "stream x memory 1 address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s1m1ar::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s1m1ar::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct S1m1arSpec;
impl crate::RegisterSpec for S1m1arSpec {
    type Ux = u32;
    const OFFSET: u64 = 56u64;
}
#[doc = "`read()` method returns [`s1m1ar::R`](R) reader structure"]
impl crate::Readable for S1m1arSpec {}
#[doc = "`write(|w| ..)` method takes [`s1m1ar::W`](W) writer structure"]
impl crate::Writable for S1m1arSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets S1M1AR to value 0"]
impl crate::Resettable for S1m1arSpec {
    const RESET_VALUE: u32 = 0;
}
