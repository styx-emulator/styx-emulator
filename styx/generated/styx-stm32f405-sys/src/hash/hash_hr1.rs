// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `HASH_HR1` reader"]
pub type R = crate::R<HashHr1Spec>;
#[doc = "Register `HASH_HR1` writer"]
pub type W = crate::W<HashHr1Spec>;
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
    pub fn h1(&mut self) -> H1W<HashHr1Spec> {
        H1W::new(self, 0)
    }
}
#[doc = "read-only\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hash_hr1::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HashHr1Spec;
impl crate::RegisterSpec for HashHr1Spec {
    type Ux = u32;
    const OFFSET: u64 = 788u64;
}
#[doc = "`read()` method returns [`hash_hr1::R`](R) reader structure"]
impl crate::Readable for HashHr1Spec {}
#[doc = "`reset()` method sets HASH_HR1 to value 0"]
impl crate::Resettable for HashHr1Spec {
    const RESET_VALUE: u32 = 0;
}
