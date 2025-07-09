// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR11` reader"]
pub type R = crate::R<Csr11Spec>;
#[doc = "Register `CSR11` writer"]
pub type W = crate::W<Csr11Spec>;
#[doc = "Field `CSR11` reader - CSR11"]
pub type Csr11R = crate::FieldReader<u32>;
#[doc = "Field `CSR11` writer - CSR11"]
pub type Csr11W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR11"]
    #[inline(always)]
    pub fn csr11(&self) -> Csr11R {
        Csr11R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR11"]
    #[inline(always)]
    #[must_use]
    pub fn csr11(&mut self) -> Csr11W<Csr11Spec> {
        Csr11W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr11::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr11::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr11Spec;
impl crate::RegisterSpec for Csr11Spec {
    type Ux = u32;
    const OFFSET: u64 = 292u64;
}
#[doc = "`read()` method returns [`csr11::R`](R) reader structure"]
impl crate::Readable for Csr11Spec {}
#[doc = "`write(|w| ..)` method takes [`csr11::W`](W) writer structure"]
impl crate::Writable for Csr11Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR11 to value 0"]
impl crate::Resettable for Csr11Spec {
    const RESET_VALUE: u32 = 0;
}
