// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR50` reader"]
pub type R = crate::R<Csr50Spec>;
#[doc = "Register `CSR50` writer"]
pub type W = crate::W<Csr50Spec>;
#[doc = "Field `CSR50` reader - CSR50"]
pub type Csr50R = crate::FieldReader<u32>;
#[doc = "Field `CSR50` writer - CSR50"]
pub type Csr50W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR50"]
    #[inline(always)]
    pub fn csr50(&self) -> Csr50R {
        Csr50R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR50"]
    #[inline(always)]
    #[must_use]
    pub fn csr50(&mut self) -> Csr50W<Csr50Spec> {
        Csr50W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr50::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr50::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr50Spec;
impl crate::RegisterSpec for Csr50Spec {
    type Ux = u32;
    const OFFSET: u64 = 448u64;
}
#[doc = "`read()` method returns [`csr50::R`](R) reader structure"]
impl crate::Readable for Csr50Spec {}
#[doc = "`write(|w| ..)` method takes [`csr50::W`](W) writer structure"]
impl crate::Writable for Csr50Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR50 to value 0"]
impl crate::Resettable for Csr50Spec {
    const RESET_VALUE: u32 = 0;
}
