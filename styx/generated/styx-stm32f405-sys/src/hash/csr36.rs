// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR36` reader"]
pub type R = crate::R<Csr36Spec>;
#[doc = "Register `CSR36` writer"]
pub type W = crate::W<Csr36Spec>;
#[doc = "Field `CSR36` reader - CSR36"]
pub type Csr36R = crate::FieldReader<u32>;
#[doc = "Field `CSR36` writer - CSR36"]
pub type Csr36W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR36"]
    #[inline(always)]
    pub fn csr36(&self) -> Csr36R {
        Csr36R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR36"]
    #[inline(always)]
    #[must_use]
    pub fn csr36(&mut self) -> Csr36W<Csr36Spec> {
        Csr36W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr36::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr36::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr36Spec;
impl crate::RegisterSpec for Csr36Spec {
    type Ux = u32;
    const OFFSET: u64 = 392u64;
}
#[doc = "`read()` method returns [`csr36::R`](R) reader structure"]
impl crate::Readable for Csr36Spec {}
#[doc = "`write(|w| ..)` method takes [`csr36::W`](W) writer structure"]
impl crate::Writable for Csr36Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR36 to value 0"]
impl crate::Resettable for Csr36Spec {
    const RESET_VALUE: u32 = 0;
}
