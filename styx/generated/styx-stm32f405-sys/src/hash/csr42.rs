// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR42` reader"]
pub type R = crate::R<Csr42Spec>;
#[doc = "Register `CSR42` writer"]
pub type W = crate::W<Csr42Spec>;
#[doc = "Field `CSR42` reader - CSR42"]
pub type Csr42R = crate::FieldReader<u32>;
#[doc = "Field `CSR42` writer - CSR42"]
pub type Csr42W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR42"]
    #[inline(always)]
    pub fn csr42(&self) -> Csr42R {
        Csr42R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR42"]
    #[inline(always)]
    #[must_use]
    pub fn csr42(&mut self) -> Csr42W<Csr42Spec> {
        Csr42W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr42::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr42::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr42Spec;
impl crate::RegisterSpec for Csr42Spec {
    type Ux = u32;
    const OFFSET: u64 = 416u64;
}
#[doc = "`read()` method returns [`csr42::R`](R) reader structure"]
impl crate::Readable for Csr42Spec {}
#[doc = "`write(|w| ..)` method takes [`csr42::W`](W) writer structure"]
impl crate::Writable for Csr42Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR42 to value 0"]
impl crate::Resettable for Csr42Spec {
    const RESET_VALUE: u32 = 0;
}
