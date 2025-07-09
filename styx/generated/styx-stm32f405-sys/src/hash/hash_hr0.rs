// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `HASH_HR0` reader"]
pub type R = crate::R<HashHr0Spec>;
#[doc = "Register `HASH_HR0` writer"]
pub type W = crate::W<HashHr0Spec>;
#[doc = "Field `H0` reader - H0"]
pub type H0R = crate::FieldReader<u32>;
#[doc = "Field `H0` writer - H0"]
pub type H0W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - H0"]
    #[inline(always)]
    pub fn h0(&self) -> H0R {
        H0R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - H0"]
    #[inline(always)]
    #[must_use]
    pub fn h0(&mut self) -> H0W<HashHr0Spec> {
        H0W::new(self, 0)
    }
}
#[doc = "HASH digest register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hash_hr0::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HashHr0Spec;
impl crate::RegisterSpec for HashHr0Spec {
    type Ux = u32;
    const OFFSET: u64 = 784u64;
}
#[doc = "`read()` method returns [`hash_hr0::R`](R) reader structure"]
impl crate::Readable for HashHr0Spec {}
#[doc = "`reset()` method sets HASH_HR0 to value 0"]
impl crate::Resettable for HashHr0Spec {
    const RESET_VALUE: u32 = 0;
}
