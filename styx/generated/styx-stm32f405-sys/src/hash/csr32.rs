// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR32` reader"]
pub type R = crate::R<Csr32Spec>;
#[doc = "Register `CSR32` writer"]
pub type W = crate::W<Csr32Spec>;
#[doc = "Field `CSR32` reader - CSR32"]
pub type Csr32R = crate::FieldReader<u32>;
#[doc = "Field `CSR32` writer - CSR32"]
pub type Csr32W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR32"]
    #[inline(always)]
    pub fn csr32(&self) -> Csr32R {
        Csr32R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR32"]
    #[inline(always)]
    #[must_use]
    pub fn csr32(&mut self) -> Csr32W<Csr32Spec> {
        Csr32W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr32::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr32::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr32Spec;
impl crate::RegisterSpec for Csr32Spec {
    type Ux = u32;
    const OFFSET: u64 = 376u64;
}
#[doc = "`read()` method returns [`csr32::R`](R) reader structure"]
impl crate::Readable for Csr32Spec {}
#[doc = "`write(|w| ..)` method takes [`csr32::W`](W) writer structure"]
impl crate::Writable for Csr32Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR32 to value 0"]
impl crate::Resettable for Csr32Spec {
    const RESET_VALUE: u32 = 0;
}
