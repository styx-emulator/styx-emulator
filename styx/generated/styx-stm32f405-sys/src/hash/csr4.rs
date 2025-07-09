// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CSR4` reader"]
pub type R = crate::R<Csr4Spec>;
#[doc = "Register `CSR4` writer"]
pub type W = crate::W<Csr4Spec>;
#[doc = "Field `CSR4` reader - CSR4"]
pub type Csr4R = crate::FieldReader<u32>;
#[doc = "Field `CSR4` writer - CSR4"]
pub type Csr4W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - CSR4"]
    #[inline(always)]
    pub fn csr4(&self) -> Csr4R {
        Csr4R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - CSR4"]
    #[inline(always)]
    #[must_use]
    pub fn csr4(&mut self) -> Csr4W<Csr4Spec> {
        Csr4W::new(self, 0)
    }
}
#[doc = "context swap registers\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`csr4::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`csr4::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Csr4Spec;
impl crate::RegisterSpec for Csr4Spec {
    type Ux = u32;
    const OFFSET: u64 = 264u64;
}
#[doc = "`read()` method returns [`csr4::R`](R) reader structure"]
impl crate::Readable for Csr4Spec {}
#[doc = "`write(|w| ..)` method takes [`csr4::W`](W) writer structure"]
impl crate::Writable for Csr4Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CSR4 to value 0"]
impl crate::Resettable for Csr4Spec {
    const RESET_VALUE: u32 = 0;
}
