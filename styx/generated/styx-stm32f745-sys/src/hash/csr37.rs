// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR37` reader"]
pub type R = crate::R<Csr37Spec>;
#[doc = "Register `CSR37` writer"]
pub type W = crate::W<Csr37Spec>;
#[doc = "Field `CSR37` reader - CSR37"]
pub type Csr37R = crate::FieldReader<u32>;
#[doc = "Field `CSR37` writer - CSR37"]
pub type Csr37W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR37"]
    #[inline(always)]
    pub fn csr37(&self) -> Csr37R {
        Csr37R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR37"]
    #[inline(always)]
    #[must_use]
    pub fn csr37(&mut self) -> Csr37W<Csr37Spec> {
        Csr37W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr37::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr37::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr37Spec;
impl crate::RegisterSpec for Csr37Spec {
    type Ux = u32;
    const OFFSET: u64 = 396u64;
}
#[doc = "`read()` method returns [`csr37::R`](R) reader structure"]
impl crate::Readable for Csr37Spec {}
#[doc = "`write(|w| ..)` method takes [`csr37::W`](W) writer structure"]
impl crate::Writable for Csr37Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR37 to value 0"]
impl crate::Resettable for Csr37Spec {
    const RESET_VALUE: u32 = 0;
}
