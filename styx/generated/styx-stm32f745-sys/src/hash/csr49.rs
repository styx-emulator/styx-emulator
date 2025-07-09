// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR49` reader"]
pub type R = crate::R<Csr49Spec>;
#[doc = "Register `CSR49` writer"]
pub type W = crate::W<Csr49Spec>;
#[doc = "Field `CSR49` reader - CSR49"]
pub type Csr49R = crate::FieldReader<u32>;
#[doc = "Field `CSR49` writer - CSR49"]
pub type Csr49W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR49"]
    #[inline(always)]
    pub fn csr49(&self) -> Csr49R {
        Csr49R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR49"]
    #[inline(always)]
    #[must_use]
    pub fn csr49(&mut self) -> Csr49W<Csr49Spec> {
        Csr49W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr49::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr49::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr49Spec;
impl crate::RegisterSpec for Csr49Spec {
    type Ux = u32;
    const OFFSET: u64 = 444u64;
}
#[doc = "`read()` method returns [`csr49::R`](R) reader structure"]
impl crate::Readable for Csr49Spec {}
#[doc = "`write(|w| ..)` method takes [`csr49::W`](W) writer structure"]
impl crate::Writable for Csr49Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR49 to value 0"]
impl crate::Resettable for Csr49Spec {
    const RESET_VALUE: u32 = 0;
}
