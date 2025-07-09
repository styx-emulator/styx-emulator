// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `HR1` reader"]
pub type R = crate::R<Hr1Spec>;
#[doc = "Register `HR1` writer"]
pub type W = crate::W<Hr1Spec>;
#[doc = "Field `H1` reader - H1"]
pub type H1R = crate::FieldReader<u32>;
#[doc = "Field `H1` writer - H1"]
pub type H1W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - H1"]
    #[inline(always)]
    pub fn h1(&self) -> H1R {
        H1R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - H1"]
    #[inline(always)]
    #[must_use]
    pub fn h1(&mut self) -> H1W<Hr1Spec> {
        H1W::new(self, 0)
    }
}
#[doc = "digest registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hr1::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Hr1Spec;
impl crate::RegisterSpec for Hr1Spec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`hr1::R`](R) reader structure"]
impl crate::Readable for Hr1Spec {}
#[doc = "`reset()` method sets HR1 to value 0"]
impl crate::Resettable for Hr1Spec {
    const RESET_VALUE: u32 = 0;
}
