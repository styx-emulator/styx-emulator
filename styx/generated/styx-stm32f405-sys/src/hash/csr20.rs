// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR20` reader"]
pub type R = crate::R<Csr20Spec>;
#[doc = "Register `CSR20` writer"]
pub type W = crate::W<Csr20Spec>;
#[doc = "Field `CSR20` reader - CSR20"]
pub type Csr20R = crate::FieldReader<u32>;
#[doc = "Field `CSR20` writer - CSR20"]
pub type Csr20W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR20"]
    #[inline(always)]
    pub fn csr20(&self) -> Csr20R {
        Csr20R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR20"]
    #[inline(always)]
    #[must_use]
    pub fn csr20(&mut self) -> Csr20W<Csr20Spec> {
        Csr20W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr20::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr20::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr20Spec;
impl crate::RegisterSpec for Csr20Spec {
    type Ux = u32;
    const OFFSET: u64 = 328u64;
}
#[doc = "`read()` method returns [`csr20::R`](R) reader structure"]
impl crate::Readable for Csr20Spec {}
#[doc = "`write(|w| ..)` method takes [`csr20::W`](W) writer structure"]
impl crate::Writable for Csr20Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR20 to value 0"]
impl crate::Resettable for Csr20Spec {
    const RESET_VALUE: u32 = 0;
}
