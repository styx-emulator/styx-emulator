// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `HASH_HR5` reader"]
pub type R = crate::R<HashHr5Spec>;
#[doc = "Register `HASH_HR5` writer"]
pub type W = crate::W<HashHr5Spec>;
#[doc = "Field `H5` reader - H5"]
pub type H5R = crate::FieldReader<u32>;
#[doc = "Field `H5` writer - H5"]
pub type H5W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - H5"]
    #[inline(always)]
    pub fn h5(&self) -> H5R {
        H5R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - H5"]
    #[inline(always)]
    #[must_use]
    pub fn h5(&mut self) -> H5W<HashHr5Spec> {
        H5W::new(self, 0)
    }
}
#[doc = "read-only\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hash_hr5::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct HashHr5Spec;
impl crate::RegisterSpec for HashHr5Spec {
    type Ux = u32;
    const OFFSET: u64 = 804u64;
}
#[doc = "`read()` method returns [`hash_hr5::R`](R) reader structure"]
impl crate::Readable for HashHr5Spec {}
#[doc = "`reset()` method sets HASH_HR5 to value 0"]
impl crate::Resettable for HashHr5Spec {
    const RESET_VALUE: u32 = 0;
}
