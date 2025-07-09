// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `S5M0AR` reader"]
pub type R = crate::R<S5m0arSpec>;
#[doc = "Register `S5M0AR` writer"]
pub type W = crate::W<S5m0arSpec>;
#[doc = "Field `M0A` reader - Memory 0 address"]
pub type M0aR = crate::FieldReader<u32>;
#[doc = "Field `M0A` writer - Memory 0 address"]
pub type M0aW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Memory 0 address"]
    #[inline(always)]
    pub fn m0a(&self) -> M0aR {
        M0aR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Memory 0 address"]
    #[inline(always)]
    #[must_use]
    pub fn m0a(&mut self) -> M0aW<S5m0arSpec> {
        M0aW::new(self, 0)
    }
}
#[doc = "stream x memory 0 address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s5m0ar::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s5m0ar::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct S5m0arSpec;
impl crate::RegisterSpec for S5m0arSpec {
    type Ux = u32;
    const OFFSET: u64 = 148u64;
}
#[doc = "`read()` method returns [`s5m0ar::R`](R) reader structure"]
impl crate::Readable for S5m0arSpec {}
#[doc = "`write(|w| ..)` method takes [`s5m0ar::W`](W) writer structure"]
impl crate::Writable for S5m0arSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets S5M0AR to value 0"]
impl crate::Resettable for S5m0arSpec {
    const RESET_VALUE: u32 = 0;
}
