// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR7` reader"]
pub type R = crate::R<Csr7Spec>;
#[doc = "Register `CSR7` writer"]
pub type W = crate::W<Csr7Spec>;
#[doc = "Field `CSR7` reader - CSR7"]
pub type Csr7R = crate::FieldReader<u32>;
#[doc = "Field `CSR7` writer - CSR7"]
pub type Csr7W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR7"]
    #[inline(always)]
    pub fn csr7(&self) -> Csr7R {
        Csr7R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR7"]
    #[inline(always)]
    #[must_use]
    pub fn csr7(&mut self) -> Csr7W<Csr7Spec> {
        Csr7W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr7::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr7::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr7Spec;
impl crate::RegisterSpec for Csr7Spec {
    type Ux = u32;
    const OFFSET: u64 = 276u64;
}
#[doc = "`read()` method returns [`csr7::R`](R) reader structure"]
impl crate::Readable for Csr7Spec {}
#[doc = "`write(|w| ..)` method takes [`csr7::W`](W) writer structure"]
impl crate::Writable for Csr7Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR7 to value 0"]
impl crate::Resettable for Csr7Spec {
    const RESET_VALUE: u32 = 0;
}
