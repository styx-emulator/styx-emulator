// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `HR4` reader"]
pub type R = crate::R<Hr4Spec>;
#[doc = "Register `HR4` writer"]
pub type W = crate::W<Hr4Spec>;
#[doc = "Field `H4` reader - H4"]
pub type H4R = crate::FieldReader<u32>;
#[doc = "Field `H4` writer - H4"]
pub type H4W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - H4"]
    #[inline(always)]
    pub fn h4(&self) -> H4R {
        H4R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - H4"]
    #[inline(always)]
    #[must_use]
    pub fn h4(&mut self) -> H4W<Hr4Spec> {
        H4W::new(self, 0)
    }
}
#[doc = "digest registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hr4::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Hr4Spec;
impl crate::RegisterSpec for Hr4Spec {
    type Ux = u32;
    const OFFSET: u64 = 28u64;
}
#[doc = "`read()` method returns [`hr4::R`](R) reader structure"]
impl crate::Readable for Hr4Spec {}
#[doc = "`reset()` method sets HR4 to value 0"]
impl crate::Resettable for Hr4Spec {
    const RESET_VALUE: u32 = 0;
}
