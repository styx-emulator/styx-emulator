// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR48` reader"]
pub type R = crate::R<Csr48Spec>;
#[doc = "Register `CSR48` writer"]
pub type W = crate::W<Csr48Spec>;
#[doc = "Field `CSR48` reader - CSR48"]
pub type Csr48R = crate::FieldReader<u32>;
#[doc = "Field `CSR48` writer - CSR48"]
pub type Csr48W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR48"]
    #[inline(always)]
    pub fn csr48(&self) -> Csr48R {
        Csr48R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR48"]
    #[inline(always)]
    #[must_use]
    pub fn csr48(&mut self) -> Csr48W<Csr48Spec> {
        Csr48W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr48::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr48::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr48Spec;
impl crate::RegisterSpec for Csr48Spec {
    type Ux = u32;
    const OFFSET: u64 = 440u64;
}
#[doc = "`read()` method returns [`csr48::R`](R) reader structure"]
impl crate::Readable for Csr48Spec {}
#[doc = "`write(|w| ..)` method takes [`csr48::W`](W) writer structure"]
impl crate::Writable for Csr48Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR48 to value 0"]
impl crate::Resettable for Csr48Spec {
    const RESET_VALUE: u32 = 0;
}
