// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR23` reader"]
pub type R = crate::R<Csr23Spec>;
#[doc = "Register `CSR23` writer"]
pub type W = crate::W<Csr23Spec>;
#[doc = "Field `CSR23` reader - CSR23"]
pub type Csr23R = crate::FieldReader<u32>;
#[doc = "Field `CSR23` writer - CSR23"]
pub type Csr23W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR23"]
    #[inline(always)]
    pub fn csr23(&self) -> Csr23R {
        Csr23R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR23"]
    #[inline(always)]
    #[must_use]
    pub fn csr23(&mut self) -> Csr23W<Csr23Spec> {
        Csr23W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr23::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr23::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr23Spec;
impl crate::RegisterSpec for Csr23Spec {
    type Ux = u32;
    const OFFSET: u64 = 340u64;
}
#[doc = "`read()` method returns [`csr23::R`](R) reader structure"]
impl crate::Readable for Csr23Spec {}
#[doc = "`write(|w| ..)` method takes [`csr23::W`](W) writer structure"]
impl crate::Writable for Csr23Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR23 to value 0"]
impl crate::Resettable for Csr23Spec {
    const RESET_VALUE: u32 = 0;
}
