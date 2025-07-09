// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR21` reader"]
pub type R = crate::R<Csr21Spec>;
#[doc = "Register `CSR21` writer"]
pub type W = crate::W<Csr21Spec>;
#[doc = "Field `CSR21` reader - CSR21"]
pub type Csr21R = crate::FieldReader<u32>;
#[doc = "Field `CSR21` writer - CSR21"]
pub type Csr21W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR21"]
    #[inline(always)]
    pub fn csr21(&self) -> Csr21R {
        Csr21R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR21"]
    #[inline(always)]
    #[must_use]
    pub fn csr21(&mut self) -> Csr21W<Csr21Spec> {
        Csr21W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr21::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr21::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr21Spec;
impl crate::RegisterSpec for Csr21Spec {
    type Ux = u32;
    const OFFSET: u64 = 332u64;
}
#[doc = "`read()` method returns [`csr21::R`](R) reader structure"]
impl crate::Readable for Csr21Spec {}
#[doc = "`write(|w| ..)` method takes [`csr21::W`](W) writer structure"]
impl crate::Writable for Csr21Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR21 to value 0"]
impl crate::Resettable for Csr21Spec {
    const RESET_VALUE: u32 = 0;
}
