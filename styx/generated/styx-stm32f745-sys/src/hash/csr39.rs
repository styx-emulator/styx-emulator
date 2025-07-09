// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR39` reader"]
pub type R = crate::R<Csr39Spec>;
#[doc = "Register `CSR39` writer"]
pub type W = crate::W<Csr39Spec>;
#[doc = "Field `CSR39` reader - CSR39"]
pub type Csr39R = crate::FieldReader<u32>;
#[doc = "Field `CSR39` writer - CSR39"]
pub type Csr39W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR39"]
    #[inline(always)]
    pub fn csr39(&self) -> Csr39R {
        Csr39R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR39"]
    #[inline(always)]
    #[must_use]
    pub fn csr39(&mut self) -> Csr39W<Csr39Spec> {
        Csr39W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr39::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr39::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr39Spec;
impl crate::RegisterSpec for Csr39Spec {
    type Ux = u32;
    const OFFSET: u64 = 404u64;
}
#[doc = "`read()` method returns [`csr39::R`](R) reader structure"]
impl crate::Readable for Csr39Spec {}
#[doc = "`write(|w| ..)` method takes [`csr39::W`](W) writer structure"]
impl crate::Writable for Csr39Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR39 to value 0"]
impl crate::Resettable for Csr39Spec {
    const RESET_VALUE: u32 = 0;
}
