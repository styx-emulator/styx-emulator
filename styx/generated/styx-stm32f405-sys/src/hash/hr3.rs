// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `HR3` reader"]
pub type R = crate::R<Hr3Spec>;
#[doc = "Register `HR3` writer"]
pub type W = crate::W<Hr3Spec>;
#[doc = "Field `H3` reader - H3"]
pub type H3R = crate::FieldReader<u32>;
#[doc = "Field `H3` writer - H3"]
pub type H3W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - H3"]
    #[inline(always)]
    pub fn h3(&self) -> H3R {
        H3R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - H3"]
    #[inline(always)]
    #[must_use]
    pub fn h3(&mut self) -> H3W<Hr3Spec> {
        H3W::new(self, 0)
    }
}
#[doc = "digest registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hr3::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Hr3Spec;
impl crate::RegisterSpec for Hr3Spec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`hr3::R`](R) reader structure"]
impl crate::Readable for Hr3Spec {}
#[doc = "`reset()` method sets HR3 to value 0"]
impl crate::Resettable for Hr3Spec {
    const RESET_VALUE: u32 = 0;
}
