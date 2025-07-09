// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR22` reader"]
pub type R = crate::R<Csr22Spec>;
#[doc = "Register `CSR22` writer"]
pub type W = crate::W<Csr22Spec>;
#[doc = "Field `CSR22` reader - CSR22"]
pub type Csr22R = crate::FieldReader<u32>;
#[doc = "Field `CSR22` writer - CSR22"]
pub type Csr22W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR22"]
    #[inline(always)]
    pub fn csr22(&self) -> Csr22R {
        Csr22R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR22"]
    #[inline(always)]
    #[must_use]
    pub fn csr22(&mut self) -> Csr22W<Csr22Spec> {
        Csr22W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr22::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr22::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr22Spec;
impl crate::RegisterSpec for Csr22Spec {
    type Ux = u32;
    const OFFSET: u64 = 336u64;
}
#[doc = "`read()` method returns [`csr22::R`](R) reader structure"]
impl crate::Readable for Csr22Spec {}
#[doc = "`write(|w| ..)` method takes [`csr22::W`](W) writer structure"]
impl crate::Writable for Csr22Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR22 to value 0"]
impl crate::Resettable for Csr22Spec {
    const RESET_VALUE: u32 = 0;
}
