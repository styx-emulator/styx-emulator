// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR19` reader"]
pub type R = crate::R<Csr19Spec>;
#[doc = "Register `CSR19` writer"]
pub type W = crate::W<Csr19Spec>;
#[doc = "Field `CSR19` reader - CSR19"]
pub type Csr19R = crate::FieldReader<u32>;
#[doc = "Field `CSR19` writer - CSR19"]
pub type Csr19W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR19"]
    #[inline(always)]
    pub fn csr19(&self) -> Csr19R {
        Csr19R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR19"]
    #[inline(always)]
    #[must_use]
    pub fn csr19(&mut self) -> Csr19W<Csr19Spec> {
        Csr19W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr19::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr19::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr19Spec;
impl crate::RegisterSpec for Csr19Spec {
    type Ux = u32;
    const OFFSET: u64 = 324u64;
}
#[doc = "`read()` method returns [`csr19::R`](R) reader structure"]
impl crate::Readable for Csr19Spec {}
#[doc = "`write(|w| ..)` method takes [`csr19::W`](W) writer structure"]
impl crate::Writable for Csr19Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR19 to value 0"]
impl crate::Resettable for Csr19Spec {
    const RESET_VALUE: u32 = 0;
}
