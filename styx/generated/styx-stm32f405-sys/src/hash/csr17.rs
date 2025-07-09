// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR17` reader"]
pub type R = crate::R<Csr17Spec>;
#[doc = "Register `CSR17` writer"]
pub type W = crate::W<Csr17Spec>;
#[doc = "Field `CSR17` reader - CSR17"]
pub type Csr17R = crate::FieldReader<u32>;
#[doc = "Field `CSR17` writer - CSR17"]
pub type Csr17W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR17"]
    #[inline(always)]
    pub fn csr17(&self) -> Csr17R {
        Csr17R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR17"]
    #[inline(always)]
    #[must_use]
    pub fn csr17(&mut self) -> Csr17W<Csr17Spec> {
        Csr17W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr17::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr17::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr17Spec;
impl crate::RegisterSpec for Csr17Spec {
    type Ux = u32;
    const OFFSET: u64 = 316u64;
}
#[doc = "`read()` method returns [`csr17::R`](R) reader structure"]
impl crate::Readable for Csr17Spec {}
#[doc = "`write(|w| ..)` method takes [`csr17::W`](W) writer structure"]
impl crate::Writable for Csr17Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR17 to value 0"]
impl crate::Resettable for Csr17Spec {
    const RESET_VALUE: u32 = 0;
}
