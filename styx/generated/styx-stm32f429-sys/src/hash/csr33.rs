// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR33` reader"]
pub type R = crate::R<Csr33Spec>;
#[doc = "Register `CSR33` writer"]
pub type W = crate::W<Csr33Spec>;
#[doc = "Field `CSR33` reader - CSR33"]
pub type Csr33R = crate::FieldReader<u32>;
#[doc = "Field `CSR33` writer - CSR33"]
pub type Csr33W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR33"]
    #[inline(always)]
    pub fn csr33(&self) -> Csr33R {
        Csr33R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR33"]
    #[inline(always)]
    #[must_use]
    pub fn csr33(&mut self) -> Csr33W<Csr33Spec> {
        Csr33W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr33::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr33::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr33Spec;
impl crate::RegisterSpec for Csr33Spec {
    type Ux = u32;
    const OFFSET: u64 = 380u64;
}
#[doc = "`read()` method returns [`csr33::R`](R) reader structure"]
impl crate::Readable for Csr33Spec {}
#[doc = "`write(|w| ..)` method takes [`csr33::W`](W) writer structure"]
impl crate::Writable for Csr33Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR33 to value 0"]
impl crate::Resettable for Csr33Spec {
    const RESET_VALUE: u32 = 0;
}
