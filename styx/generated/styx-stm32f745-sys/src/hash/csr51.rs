// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR51` reader"]
pub type R = crate::R<Csr51Spec>;
#[doc = "Register `CSR51` writer"]
pub type W = crate::W<Csr51Spec>;
#[doc = "Field `CSR51` reader - CSR51"]
pub type Csr51R = crate::FieldReader<u32>;
#[doc = "Field `CSR51` writer - CSR51"]
pub type Csr51W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR51"]
    #[inline(always)]
    pub fn csr51(&self) -> Csr51R {
        Csr51R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR51"]
    #[inline(always)]
    #[must_use]
    pub fn csr51(&mut self) -> Csr51W<Csr51Spec> {
        Csr51W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr51::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr51::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr51Spec;
impl crate::RegisterSpec for Csr51Spec {
    type Ux = u32;
    const OFFSET: u64 = 452u64;
}
#[doc = "`read()` method returns [`csr51::R`](R) reader structure"]
impl crate::Readable for Csr51Spec {}
#[doc = "`write(|w| ..)` method takes [`csr51::W`](W) writer structure"]
impl crate::Writable for Csr51Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR51 to value 0"]
impl crate::Resettable for Csr51Spec {
    const RESET_VALUE: u32 = 0;
}
