// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR9` reader"]
pub type R = crate::R<Csr9Spec>;
#[doc = "Register `CSR9` writer"]
pub type W = crate::W<Csr9Spec>;
#[doc = "Field `CSR9` reader - CSR9"]
pub type Csr9R = crate::FieldReader<u32>;
#[doc = "Field `CSR9` writer - CSR9"]
pub type Csr9W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR9"]
    #[inline(always)]
    pub fn csr9(&self) -> Csr9R {
        Csr9R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR9"]
    #[inline(always)]
    #[must_use]
    pub fn csr9(&mut self) -> Csr9W<Csr9Spec> {
        Csr9W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr9::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr9::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr9Spec;
impl crate::RegisterSpec for Csr9Spec {
    type Ux = u32;
    const OFFSET: u64 = 284u64;
}
#[doc = "`read()` method returns [`csr9::R`](R) reader structure"]
impl crate::Readable for Csr9Spec {}
#[doc = "`write(|w| ..)` method takes [`csr9::W`](W) writer structure"]
impl crate::Writable for Csr9Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR9 to value 0"]
impl crate::Resettable for Csr9Spec {
    const RESET_VALUE: u32 = 0;
}
