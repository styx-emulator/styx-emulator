// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR43` reader"]
pub type R = crate::R<Csr43Spec>;
#[doc = "Register `CSR43` writer"]
pub type W = crate::W<Csr43Spec>;
#[doc = "Field `CSR43` reader - CSR43"]
pub type Csr43R = crate::FieldReader<u32>;
#[doc = "Field `CSR43` writer - CSR43"]
pub type Csr43W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR43"]
    #[inline(always)]
    pub fn csr43(&self) -> Csr43R {
        Csr43R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR43"]
    #[inline(always)]
    #[must_use]
    pub fn csr43(&mut self) -> Csr43W<Csr43Spec> {
        Csr43W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr43::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr43::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr43Spec;
impl crate::RegisterSpec for Csr43Spec {
    type Ux = u32;
    const OFFSET: u64 = 420u64;
}
#[doc = "`read()` method returns [`csr43::R`](R) reader structure"]
impl crate::Readable for Csr43Spec {}
#[doc = "`write(|w| ..)` method takes [`csr43::W`](W) writer structure"]
impl crate::Writable for Csr43Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR43 to value 0"]
impl crate::Resettable for Csr43Spec {
    const RESET_VALUE: u32 = 0;
}
