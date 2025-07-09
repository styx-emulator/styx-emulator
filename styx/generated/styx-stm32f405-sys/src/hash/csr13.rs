// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR13` reader"]
pub type R = crate::R<Csr13Spec>;
#[doc = "Register `CSR13` writer"]
pub type W = crate::W<Csr13Spec>;
#[doc = "Field `CSR13` reader - CSR13"]
pub type Csr13R = crate::FieldReader<u32>;
#[doc = "Field `CSR13` writer - CSR13"]
pub type Csr13W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR13"]
    #[inline(always)]
    pub fn csr13(&self) -> Csr13R {
        Csr13R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR13"]
    #[inline(always)]
    #[must_use]
    pub fn csr13(&mut self) -> Csr13W<Csr13Spec> {
        Csr13W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr13::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr13::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr13Spec;
impl crate::RegisterSpec for Csr13Spec {
    type Ux = u32;
    const OFFSET: u64 = 300u64;
}
#[doc = "`read()` method returns [`csr13::R`](R) reader structure"]
impl crate::Readable for Csr13Spec {}
#[doc = "`write(|w| ..)` method takes [`csr13::W`](W) writer structure"]
impl crate::Writable for Csr13Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR13 to value 0"]
impl crate::Resettable for Csr13Spec {
    const RESET_VALUE: u32 = 0;
}
